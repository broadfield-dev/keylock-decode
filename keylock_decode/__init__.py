import logging

from .core import decode_from_image_pil, decode_from_image_path

__version__ = "0.1.0"
__all__ = ['decode_from_image_pil', 'decode_from_image_path', '__version__']

logging.getLogger(__name__).addHandler(logging.NullHandler())
