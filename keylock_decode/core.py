# keylock/core.py
import io
import json
import os
import struct
import logging
import traceback
import base64

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidTag

from PIL import Image, ImageDraw, ImageFont
import numpy as np

logger = logging.getLogger(__name__)
if not logger.hasHandlers():
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(module)s - %(lineno)d - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

SALT_SIZE = 16; NONCE_SIZE = 12; TAG_SIZE = 16; KEY_SIZE = 32
PBKDF2_ITERATIONS = 390_000; LENGTH_HEADER_SIZE = 4
PREFERRED_FONTS = ["Verdana", "Arial", "DejaVu Sans", "Calibri", "Helvetica", "Roboto-Regular", "sans-serif"]
MAX_KEYS_TO_DISPLAY_OVERLAY = 12

def _get_font(preferred_fonts, base_size):
    fp = None
    for n in preferred_fonts:
        try: ImageFont.truetype(n.lower()+".ttf",10); fp=n.lower()+".ttf"; break
        except IOError:
            try: ImageFont.truetype(n,10); fp=n; break
            except IOError: continue
    if fp:
        try: return ImageFont.truetype(fp, int(base_size)) # Ensure integer size
        except IOError: logger.warning(f"Font '{fp}' load failed with size {base_size}. Defaulting.")
    return ImageFont.load_default() # load_default does not take size argument in older Pillow

def set_pil_image_format_to_png(image:Image.Image)->Image.Image:
    buf=io.BytesIO(); image.save(buf,format='PNG'); buf.seek(0)
    reloaded=Image.open(buf); reloaded.format="PNG"; return reloaded

def _derive_key(pw:str,salt:bytes)->bytes:
    kdf=PBKDF2HMAC(algorithm=hashes.SHA256(),length=KEY_SIZE,salt=salt,iterations=PBKDF2_ITERATIONS)
    return kdf.derive(pw.encode('utf-8'))

def encrypt_data(data:bytes,pw:str)->bytes:
    s=os.urandom(SALT_SIZE);k=_derive_key(pw,s);a=AESGCM(k);n=os.urandom(NONCE_SIZE)
    ct=a.encrypt(n,data,None); return s+n+ct

def decrypt_data(payload:bytes,pw:str)->bytes:
    ml=SALT_SIZE+NONCE_SIZE+TAG_SIZE;
    if len(payload)<ml: raise ValueError("Payload too short.")
    s,n,ct_tag=payload[:SALT_SIZE],payload[SALT_SIZE:SALT_SIZE+NONCE_SIZE],payload[SALT_SIZE+NONCE_SIZE:]
    k=_derive_key(pw,s);a=AESGCM(k)
    try: return a.decrypt(n,ct_tag,None)
    except InvalidTag: raise ValueError("Decryption failed: Invalid password/corrupted data.")
    except Exception as e: logger.error(f"Decrypt error: {e}",exc_info=True); raise

def _d2b(d:bytes)->str: return ''.join(format(b,'08b') for b in d)
def _b2B(b:str)->bytes:
    if len(b)%8!=0: raise ValueError("Bits not multiple of 8.")
    return bytes(int(b[i:i+8],2) for i in range(0,len(b),8))

def embed_data_in_image(img_obj:Image.Image,data:bytes)->Image.Image:
    img=img_obj.convert("RGB");px=np.array(img);fpx=px.ravel()
    lb=struct.pack('>I',len(data));fp=lb+data;db=_d2b(fp);nb=len(db)
    if nb>len(fpx): raise ValueError(f"Data too large: {nb} bits needed, {len(fpx)} available.")
    for i in range(nb): fpx[i]=(fpx[i]&0xFE)|int(db[i])
    spx=fpx.reshape(px.shape); return Image.fromarray(spx.astype(np.uint8),'RGB')

def extract_data_from_image(img_obj:Image.Image)->bytes:
    img=img_obj.convert("RGB");px=np.array(img);fpx=px.ravel()
    hbc=LENGTH_HEADER_SIZE*8
    if len(fpx)<hbc: raise ValueError("Image too small for header.")
    lb="".join(str(fpx[i]&1) for i in range(hbc))
    try: pl=struct.unpack('>I',_b2B(lb))[0]
    except Exception as e: raise ValueError(f"Header decode error: {e}")
    if pl==0: return b""
    if pl>(len(fpx)-hbc)/8: raise ValueError("Header len corrupted or > capacity.")
    tpb=pl*8; so=hbc; eo=so+tpb
    if len(fpx)<eo: raise ValueError("Image truncated or header corrupted.")
    pb="".join(str(fpx[i]&1) for i in range(so,eo)); return _b2B(pb)

def parse_kv_string_to_dict(kv_str:str)->dict:
    if not kv_str or not kv_str.strip(): return {}
    dd={};
    for ln,ol in enumerate(kv_str.splitlines(),1):
        l=ol.strip()
        if not l or l.startswith('#'): continue
        lc=l.split('#',1)[0].strip();
        if not lc: continue
        p=lc.split('=',1) if '=' in lc else lc.split(':',1) if ':' in lc else []
        if len(p)!=2: raise ValueError(f"L{ln}: Invalid format '{ol}'.")
        k,v=p[0].strip(),p[1].strip()
        if not k: raise ValueError(f"L{ln}: Empty key in '{ol}'.")
        if len(v)>=2 and v[0]==v[-1] and v.startswith(("'",'"')): v=v[1:-1]
        dd[k]=v
    return dd

def generate_keylock_carrier_image(w=800,h=600,msg="KeyLock Wallet")->Image.Image:
    cs,ce=(30,40,50),(70,80,90);img=Image.new("RGB",(w,h),cs);draw=ImageDraw.Draw(img)
    for y_ in range(h):
        i=y_/float(h-1) if h>1 else .5;r_,g_,b_=(int(s_*(1-i)+e_*(i)) for s_,e_ in zip(cs,ce))
        draw.line([(0,y_),(w,y_)],fill=(r_,g_,b_))
    ib=min(w,h)//7;icx,icy=w//2,h//3;cr=ib//2;cb=[(icx-cr,icy-cr),(icx+cr,icy+cr)]
    rw,rh=ib//4,ib//2;rty=icy+int(cr*.2);rb=[(icx-rw//2,rty),(icx+rw//2,rty+rh)]
    kc,ko=(190,195,200),(120,125,130);ow=max(1,int(ib/30))
    draw.ellipse(cb,fill=kc,outline=ko,width=ow);draw.rectangle(rb,fill=kc,outline=ko,width=ow)
    fs=max(16,min(int(w/18),h//8));fnt=_get_font(PREFERRED_FONTS,fs)
    tc=(225,230,235);sc=(max(0,s_-20) for s_ in cs);tx,ty=w/2,h*.68;so=max(1,int(fs/25))
    try:draw.text((tx+so,ty+so),msg,font=fnt,fill=tuple(sc),anchor="mm");draw.text((tx,ty),msg,font=fnt,fill=tc,anchor="mm")
    except AttributeError:
        bbox_textsize = fnt.getbbox(msg) if hasattr(fnt, 'getbbox') else (0,0) + draw.textsize(msg, font=fnt)
        tw,th=bbox_textsize[2]-bbox_textsize[0],bbox_textsize[3]-bbox_textsize[1]
        ax,ay=(w-tw)/2,ty-(th/2)
        draw.text((ax+so,ay+so),msg,font=fnt,fill=tuple(sc));draw.text((ax,ay),msg,font=fnt,fill=tc) # Note: textsize/getbbox might not fully match anchor="mm" vertical alignment.
    return img

def _get_text_width(draw_obj, text_str, font_obj):
    if hasattr(font_obj, 'getlength'): # Pillow 10.0.0+ moved getlength to font object
        return font_obj.getlength(text_str)
    elif hasattr(draw_obj, 'textlength'):  # Pillow 9.2.0+
        return draw_obj.textlength(text_str, font=font_obj)
    elif hasattr(draw_obj, 'textbbox'): # Pillow 8.0.0+
        bbox = draw_obj.textbbox((0, 0), text_str, font=font_obj)
        return bbox[2] - bbox[0]
    else:  # Older Pillow
        try:
            width, _ = draw_obj.textsize(text_str, font=font_obj)
            return width
        except AttributeError: # If draw_obj itself doesn't have textsize (e.g. very old PIL)
            if hasattr(font_obj, 'getsize'): # font.getsize()
                width, _ = font_obj.getsize(text_str)
                return width
            return 20 # fallback

def _get_text_height(draw_obj, text_str, font_obj):
    if hasattr(draw_obj, 'textbbox'): # Pillow 8.0.0+
        bbox = draw_obj.textbbox((0,0), text_str, font=font_obj) # Using (0,0) as anchor for simplicity
        return bbox[3] - bbox[1] # height = bottom - top
    else: # Older Pillow
        try:
            _, height = draw_obj.textsize(text_str, font=font_obj)
            return height
        except AttributeError:
            if hasattr(font_obj, 'getsize'):
                _, height = font_obj.getsize(text_str)
                return height
            return 10 # fallback


def draw_key_list_dropdown_overlay(image: Image.Image, keys: list[str] = None, title: str = "Data Embedded") -> Image.Image:
    if not title and (keys is None or not keys):
        return set_pil_image_format_to_png(image.copy())

    img_overlayed = image.copy(); draw = ImageDraw.Draw(img_overlayed)
    margin = 10; padding = {'title_x':10,'title_y':6,'key_x':10,'key_y':5}; line_spacing = 4
    title_bg_color=(60,60,60); title_text_color=(230,230,90)
    key_list_bg_color=(50,50,50); key_text_color=(210,210,210); ellipsis_color=(170,170,170)
    
    # --- Overlay Width Calculation ---
    OVERLAY_TARGET_WIDTH_RATIO = 0.30
    MIN_OVERLAY_WIDTH_PX = 180 # Increased minimum width
    MAX_OVERLAY_WIDTH_PX = 500 # Increased maximum width

    overlay_box_width = int(image.width * OVERLAY_TARGET_WIDTH_RATIO)
    overlay_box_width = max(MIN_OVERLAY_WIDTH_PX, overlay_box_width)
    overlay_box_width = min(MAX_OVERLAY_WIDTH_PX, overlay_box_width)
    overlay_box_width = min(overlay_box_width, image.width - 2 * margin) # Ensure it fits

    # --- Font Size Calculations ---
    TITLE_FONT_HEIGHT_RATIO = 0.030 # Fraction of image height for font sizing
    TITLE_FONT_OVERLAY_WIDTH_RATIO = 0.08 # Fraction of overlay_box_width for font sizing
    MIN_TITLE_FONT_SIZE = 14
    MAX_TITLE_FONT_SIZE = 28

    title_font_size_from_h = int(image.height * TITLE_FONT_HEIGHT_RATIO)
    title_font_size_from_w = int(overlay_box_width * TITLE_FONT_OVERLAY_WIDTH_RATIO)
    title_font_size = min(title_font_size_from_h, title_font_size_from_w)
    title_font_size = max(MIN_TITLE_FONT_SIZE, title_font_size)
    title_font_size = min(MAX_TITLE_FONT_SIZE, title_font_size)
    title_font = _get_font(PREFERRED_FONTS, title_font_size)

    KEY_FONT_HEIGHT_RATIO = 0.025
    KEY_FONT_OVERLAY_WIDTH_RATIO = 0.07
    MIN_KEY_FONT_SIZE = 12
    MAX_KEY_FONT_SIZE = 22

    key_font_size_from_h = int(image.height * KEY_FONT_HEIGHT_RATIO)
    key_font_size_from_w = int(overlay_box_width * KEY_FONT_OVERLAY_WIDTH_RATIO)
    key_font_size = min(key_font_size_from_h, key_font_size_from_w)
    key_font_size = max(MIN_KEY_FONT_SIZE, key_font_size)
    key_font_size = min(MAX_KEY_FONT_SIZE, key_font_size)
    key_font = _get_font(PREFERRED_FONTS, key_font_size)
    
    # --- Text dimensions ---
    actual_title_w = _get_text_width(draw, title, title_font)
    actual_title_h = _get_text_height(draw, title, title_font)

    disp_keys, actual_key_text_widths, total_keys_render_h, key_line_heights = [],[],0,[]
    if keys:
        temp_disp_keys=keys[:MAX_KEYS_TO_DISPLAY_OVERLAY-1]+[f"... ({len(keys)-(MAX_KEYS_TO_DISPLAY_OVERLAY-1)} more)"] if len(keys)>MAX_KEYS_TO_DISPLAY_OVERLAY else keys
        for kt in temp_disp_keys:
            disp_keys.append(kt)
            kw = _get_text_width(draw, kt, key_font)
            kh = _get_text_height(draw, kt, key_font)
            actual_key_text_widths.append(kw); key_line_heights.append(kh)
            total_keys_render_h += kh
        if len(disp_keys)>1: total_keys_render_h += line_spacing*(len(disp_keys)-1)
    
    # --- Title Bar Drawing ---
    title_bar_h = actual_title_h + 2*padding['title_y']
    title_bar_x0 = margin
    title_bar_x1 = title_bar_x0 + overlay_box_width
    title_bar_y0 = margin
    title_bar_y1 = title_bar_y0 + title_bar_h
    
    draw.rectangle([(title_bar_x0,title_bar_y0),(title_bar_x1,title_bar_y1)],fill=title_bg_color)
    
    available_width_for_title_text = overlay_box_width - 2 * padding['title_x']
    if actual_title_w <= available_width_for_title_text:
        title_text_draw_x = title_bar_x0 + padding['title_x'] + (available_width_for_title_text - actual_title_w) / 2
    else: # If title is wider than available space (even after font adjustments), left-align
        title_text_draw_x = title_bar_x0 + padding['title_x']
    title_text_draw_y = title_bar_y0 + padding['title_y']
    draw.text((title_text_draw_x, title_text_draw_y), title, font=title_font, fill=title_text_color)

    # --- Key List Drawing ---
    if disp_keys:
        key_list_box_h_ideal = total_keys_render_h + 2*padding['key_y']
        key_list_x0, key_list_x1 = title_bar_x0, title_bar_x1
        key_list_y0 = title_bar_y1 
        key_list_y1 = key_list_y0 + key_list_box_h_ideal
        
        key_list_y1 = min(key_list_y1, image.height - margin) # Ensure it fits vertically
        current_key_list_box_h = key_list_y1 - key_list_y0

        draw.rectangle([(key_list_x0,key_list_y0),(key_list_x1,key_list_y1)],fill=key_list_bg_color)
        
        current_text_y = key_list_y0 + padding['key_y']
        available_text_width_for_keys = overlay_box_width - 2 * padding['key_x']

        for i, key_text_item in enumerate(disp_keys):
            if i >= len(key_line_heights): break 
            
            current_key_h = key_line_heights[i]
            if current_text_y + current_key_h > key_list_y0 + current_key_list_box_h - padding['key_y']:
                ellipsis_h = _get_text_height(draw,"...",key_font)
                if current_text_y + ellipsis_h <= key_list_y0 + current_key_list_box_h - padding['key_y']:
                    ellipsis_w = _get_text_width(draw,"...",key_font)
                    draw.text((key_list_x0 + (overlay_box_width - ellipsis_w)/2, current_text_y), "...", font=key_font, fill=ellipsis_color)
                break 
            
            original_key_text_w = actual_key_text_widths[i]
            text_to_draw = key_text_item
            
            if original_key_text_w > available_text_width_for_keys:
                temp_text = key_text_item
                while _get_text_width(draw, temp_text + "...", key_font) > available_text_width_for_keys and len(temp_text) > 0:
                    temp_text = temp_text[:-1]
                text_to_draw = temp_text + "..." if len(temp_text) < len(key_text_item) else temp_text
            
            final_key_text_w = _get_text_width(draw, text_to_draw, key_font)
            key_text_draw_x = key_list_x0 + padding['key_x'] + max(0, (available_text_width_for_keys - final_key_text_w) / 2)
            
            text_color_to_use = ellipsis_color if "..." in text_to_draw or f"... ({len(keys)-(MAX_KEYS_TO_DISPLAY_OVERLAY-1)} more)" in key_text_item else key_text_color
            draw.text((key_text_draw_x, current_text_y), text_to_draw, font=key_font, fill=text_color_to_use)
            current_text_y += current_key_h
            if i < len(disp_keys)-1: current_text_y += line_spacing
            
    return set_pil_image_format_to_png(img_overlayed)
