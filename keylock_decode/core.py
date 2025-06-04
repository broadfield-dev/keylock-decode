import os
import struct
import json
import logging
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidTag
from PIL import Image
import numpy as np

logger = logging.getLogger(__name__)

# --- Constants for cryptographic operations and LSB steganography ---
SALT_SIZE = 16
NONCE_SIZE = 12 # Recommended for AES-GCM
TAG_SIZE = 16   # AES-GCM authentication tag size
KEY_SIZE = 32   # For AES-256
PBKDF2_ITERATIONS = 390_000 # OWASP recommendation (as of late 2023/early 2024)
LENGTH_HEADER_SIZE = 4  # Bytes to store the length of the embedded payload

# --- Internal Cryptography ---
def _derive_key(password: str, salt: bytes) -> bytes:
    """Derives a 256-bit cryptographic key from a password and salt using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode('utf-8'))

def _decrypt_data(encrypted_payload: bytes, password: str) -> bytes:
    """Decrypts payload (salt + nonce + ciphertext_with_tag) using AES-GCM."""
    if len(encrypted_payload) < SALT_SIZE + NONCE_SIZE + TAG_SIZE: # Basic sanity check
        raise ValueError("Encrypted payload is too short for valid salt, nonce, and GCM tag.")
    
    salt = encrypted_payload[:SALT_SIZE]
    nonce = encrypted_payload[SALT_SIZE : SALT_SIZE + NONCE_SIZE]
    ciphertext_with_tag = encrypted_payload[SALT_SIZE + NONCE_SIZE:]
    
    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext_with_tag, None) # No AAD
    except InvalidTag: # This indicates decryption failure (wrong key or tampered data)
        raise ValueError("Decryption failed: Invalid password or corrupted data (GCM tag mismatch).")

# --- Internal Bit/Byte Manipulation ---
def _bits_to_bytes(bits: str) -> bytes:
    """Converts a string of '0's and '1's to a byte string."""
    if len(bits) % 8 != 0:
        raise ValueError("Bit string length must be a multiple of 8 for byte conversion.")
    return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))

# --- Internal LSB Extraction ---
def _extract_encrypted_payload_from_image(image_pil: Image.Image) -> bytes:
    """Extracts the raw encrypted payload (length-prefixed) from image LSBs."""
    try:
        img_rgb = image_pil.convert("RGB") # Ensure consistent 3-channel format
    except Exception as e:
        raise IOError(f"Could not process image (ensure it's a valid format): {e}")
        
    pixels = np.array(img_rgb)
    flat_pixels = pixels.ravel() # R,G,B,R,G,B...

    len_header_bits_count = LENGTH_HEADER_SIZE * 8
    if len(flat_pixels) < len_header_bits_count:
        raise ValueError("Image is too small to contain a payload length header.")
    
    # Extract bits for the length header
    len_bits = "".join(map(str, (flat_pixels[i] & 1 for i in range(len_header_bits_count))))
    
    try:
        payload_len_bytes = _bits_to_bytes(len_bits)
        encrypted_payload_len = struct.unpack('>I', payload_len_bytes)[0] # Big-endian unsigned int
    except Exception as e: # Handles errors from _bits_to_bytes or struct.unpack
        raise ValueError(f"Could not decode payload length from image header: {e}")

    logger.info(f"Decoded payload length from header: {encrypted_payload_len} bytes.")

    # Validate decoded length against image capacity
    max_possible_payload_bytes = (len(flat_pixels) - len_header_bits_count) // 8
    if encrypted_payload_len > max_possible_payload_bytes:
        raise ValueError(f"Data length header ({encrypted_payload_len} bytes) exceeds image capacity ({max_possible_payload_bytes} bytes).")
    if encrypted_payload_len == 0:
        return b"" # No payload to extract

    # Extract the payload bits
    total_payload_bits_to_extract = encrypted_payload_len * 8
    start_idx = len_header_bits_count
    end_idx = start_idx + total_payload_bits_to_extract

    if len(flat_pixels) < end_idx: # Should be caught by previous check, but good for robustness
        raise ValueError("Image appears truncated or data length header corrupted during payload extraction.")

    payload_bits = "".join(map(str, (flat_pixels[i] & 1 for i in range(start_idx, end_idx))))
    extracted_payload = _bits_to_bytes(payload_bits)
    
    # Final sanity check on extracted length
    if len(extracted_payload) != encrypted_payload_len:
        raise ValueError("Internal consistency error: Mismatch in extracted payload length vs. expected length.")
        
    return extracted_payload

# --- Public Decoding Functions ---
def decode_from_image_pil(stego_image_pil: Image.Image, password: str, set_environment_variables: bool = False) -> tuple[dict, list[str]]:
    """
    Decodes data from a steganographic PIL Image object.

    Args:
        stego_image_pil: The PIL.Image.Image object containing the steganographic data.
        password: The password used for decryption.
        set_environment_variables: If True, attempts to set the decoded key-value pairs
                                   as environment variables for the current process.
                                   WARNING: Use with extreme caution due to security risks.

    Returns:
        A tuple: (decoded_dictionary, list_of_status_messages).
                 The dictionary contains the decoded key-value pairs.
                 The list contains human-readable status messages about the process.

    Raises:
        TypeError: If stego_image_pil is not a PIL.Image.Image object.
        IOError: If the image cannot be processed.
        ValueError: For various decoding, decryption, or data format errors.
    """
    logger.info("Starting decoding process from PIL Image object.")
    status_messages = []

    if not isinstance(stego_image_pil, Image.Image): # Type check for robustness
        raise TypeError("Input 'stego_image_pil' must be a PIL.Image.Image object.")

    encrypted_payload = _extract_encrypted_payload_from_image(stego_image_pil)
    if not encrypted_payload: # Payload length was 0
        msg = "No payload data found in the image (payload length was zero)."
        logger.info(msg)
        status_messages.append(msg)
        return {}, status_messages # Return empty dict and status

    decrypted_data_bytes = _decrypt_data(encrypted_payload, password)

    try:
        final_data_dict = json.loads(decrypted_data_bytes.decode('utf-8'))
        status_messages.append("Data successfully decrypted and deserialized.")
    except json.JSONDecodeError as e:
        raise ValueError(f"Decrypted data is not valid JSON: {e}. Raw (hex): {decrypted_data_bytes.hex()}")
    except UnicodeDecodeError as e:
        raise ValueError(f"Decrypted data is not valid UTF-8: {e}. Raw (hex): {decrypted_data_bytes.hex()}")

    if set_environment_variables:
        logger.warning("Attempting to set environment variables from decoded data. This can be a security risk.")
        env_vars_set_count = 0
        if not final_data_dict:
            status_messages.append("Decoded data is empty, no environment variables to set.")
        else:
            for key, value in final_data_dict.items():
                s_key = str(key) # Ensure keys are strings for os.environ
                s_value = str(value) # Ensure values are strings for os.environ
                
                if not isinstance(key, str) or not isinstance(value, str):
                    status_messages.append(f"Warning: Original key/value ({key!r}/{value!r}) not both strings, converted for env var: {s_key}='{s_value}'")
                try:
                    os.environ[s_key] = s_value
                    status_messages.append(f"Environment variable set: {s_key}='***' (value hidden for security in logs)") # Avoid logging sensitive values
                    logger.info(f"Environment variable set: {s_key} (value omitted from log)")
                    env_vars_set_count += 1
                except Exception as e: # Catch potential errors during os.environ assignment
                    err_msg = f"Failed to set environment variable {s_key}: {e}"
                    logger.error(err_msg)
                    status_messages.append(f"Error: {err_msg}")
            
            if env_vars_set_count > 0:
                 status_messages.append(f"Successfully set {env_vars_set_count} environment variable(s).")
            elif final_data_dict: # If data dict was not empty but nothing was set
                 status_messages.append("No valid (string key/value) environment variables were set from the decoded data.")
    
    return final_data_dict, status_messages


def decode_from_image_path(stego_image_path: str, password: str, set_environment_variables: bool = False) -> tuple[dict, list[str]]:
    """
    Convenience function to decode data from an image file path.
    Opens the image and then calls decode_from_image_pil.
    """
    logger.info(f"Attempting to decode from image path: {stego_image_path}")
    try:
        stego_image_pil = Image.open(stego_image_path)
    except FileNotFoundError:
        logger.error(f"Image file not found: {stego_image_path}")
        raise # Re-raise FileNotFoundError to be handled by caller
    except Exception as e: # Catch other PIL opening errors
        logger.error(f"Could not open or read image file '{stego_image_path}': {e}")
        raise IOError(f"Could not open or read image file '{stego_image_path}': {e}")
    
    # It can be useful to attach the filename to the PIL object for context, though not strictly necessary
    # if not hasattr(stego_image_pil, 'filename') or not stego_image_pil.filename:
    #    stego_image_pil.filename = stego_image_path
        
    return decode_from_image_pil(stego_image_pil, password, set_environment_variables)
