# KeyLock-Decode: Steganographic Data Decoder

"KeyLock-Decode" is a Python library and command-line tool designed to securely decode steganographically hidden, encrypted data from PNG images. This tool focuses specifically on the decoding process, enabling the retrieval of sensitive key-value pairs embedded within images.

It assumes the data was embedded using a compatible LSB (Least Significant Bit) steganography technique coupled with AES-GCM encryption for confidentiality and integrity.

## Features

-   Decodes data embedded in the LSBs of PNG images.
-   Decrypts data using AES-GCM; keys are derived from a user-provided password and a stored salt via PBKDF2.
-   Optionally sets decoded key-value pairs as environment variables for the current process (requires extreme caution).
-   Provides both a Python library interface for programmatic use and a command-line tool for direct execution.

## Installation

Install "KeyLock-Decode" directly from GitHub (once the repository is public):

```bash
pip install git+https://github.com/broaddfield-dev/keylock-decode.git
```

Alternatively, after cloning the repository:

```bash
git clone https://github.com/broadfield-dev/keylock-decode.git
cd keylock-decode
pip install .
```

## Library Usage

```python
from keylock_decode import decode_from_image_path, decode_from_image_pil
from PIL import Image
import logging

# --- Recommended: Configure logging for your application ---
# This allows you to see logs from the keylock_decode library.
# For verbose output including debug messages from the library:
# logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
# For informational messages only:
# logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
# If you don't configure logging, the library itself won't produce output by default.


try:
    image_file_path = "path/to/your/stego_image.png"
    password = "your_secret_password"
    
    # Option 1: Decode from an image file path
    # Set "set_environment_variables=True" to load keys into the current process environment.
    # WARNING: This is a security risk if the input is untrusted.
    decoded_data, status_msgs = decode_from_image_path(
        image_file_path, 
        password, 
        set_environment_variables=False # Defaults to False
    )
    
    print("\n--- Status Messages ---")
    for msg in status_msgs:
        print(f"- {msg}")
    
    print("\n--- Decoded Data ---")
    if decoded_data:
        for key, value in decoded_data.items():
            print(f"{key}: {value}")
    else:
        # This case is usually covered by status_msgs (e.g., "No payload data found...")
        print("No data was decoded or the decoded data was empty.")

    # Option 2: Decode from a PIL Image object (if you've already loaded it)
    # with Image.open(image_file_path) as img_pil:
    #     decoded_data_pil, status_msgs_pil = decode_from_image_pil(
    #         img_pil, 
    #         password,
    #         set_environment_variables=True # Example: setting env vars here
    #     )
    #     print("\n--- Status Messages (from PIL object) ---")
    #     for msg in status_msgs_pil:
    #         print(f"- {msg}")
    #     print("\n--- Decoded Data (from PIL object) ---")
    #     if decoded_data_pil:
    #         for key, value in decoded_data_pil.items():
    #             print(f"{key}: {value}")


except ValueError as e:
    # Handles errors from the library like bad password, corrupted data, JSON format issues
    print(f"Decoding Error: {e}")
except FileNotFoundError:
    print(f"Error: Image file not found at '{image_file_path}'")
except IOError as e:
    # Handles errors related to opening or reading the image file
    print(f"Error reading image file: {e}")
except Exception as e:
    # Catch-all for other unexpected issues
    print(f"An unexpected error occurred: {e}")

```

## Command-Line Usage

The package installs a command-line tool: "keylock-decode".

```bash
keylock-decode IMAGE_PATH PASSWORD [options]
```

**Arguments:**

-   "IMAGE_PATH": Path to the stego PNG image.
-   "PASSWORD": Password for decryption.

**Options:**

-   "--set-env": Set decoded key-value pairs as environment variables for the current process. **WARNING: Use with extreme caution due to security risks.**
-   "-o FILE, --output-file FILE": Optional path to save the decoded JSON data.
-   "-v, --verbose": Enable verbose debug logging for more detailed output.
-   "--version": Show the program's version number and exit.
-   "-h, --help": Show this help message and exit.

**Examples:**

1.  Decode data and print to console:
    ```bash
    keylock-decode ./my_secret_image.png "supersecretpassword123"
    ```

2.  Decode data, attempt to set environment variables, save output to a file, and enable verbose logging:
    ```bash
    keylock-decode ./another_image.png "anotherPass" --set-env -o decoded_data.json -v
    ```

## Security Warning: Environment Variables

The "--set-env" option (and "set_environment_variables=True" in the library) enables "KeyLock-Decode" to set the decoded key-value pairs as environment variables. This functionality should be used with **extreme caution**:

-   **Risk of Injection**: If the steganographic image or the password originates from an untrusted source, malicious actors could inject harmful environment variables ("PATH", "LD_PRELOAD", credentials, etc.). This can compromise the security of the system where "KeyLock-Decode" is run.
-   **Scope**: Environment variables set by this tool are active **only within the current running process** (the "keylock-decode" CLI or the Python script using the library) and any child processes it spawns *after* the variables are set.
-   **Non-Persistent**: These environment variables are **not** permanently set on the system. They are lost when the process terminates.
-   **Recommendation**: Only use this feature in highly controlled, trusted environments where the integrity of the input image and password can be guaranteed.

## How It Works

1.  **LSB Data Extraction**: "KeyLock-Decode" reads the least significant bits (LSBs) of the image's pixel color values. It first extracts a header containing the length of the hidden payload.
2.  **AES-GCM Decryption**: The extracted payload, which is encrypted, is decrypted using AES-GCM. A strong cryptographic key is derived from the provided password and a salt (stored with the payload) using PBKDF2-HMAC-SHA256. AES-GCM provides both confidentiality and authenticity.
3.  **Data Deserialization**: The decrypted byte string is assumed to be UTF-8 encoded JSON. It is parsed into a Python dictionary representing the original key-value pairs.
4.  **Environment Variable Setting (Optional)**: If requested, the string representations of these key-value pairs are set as environment variables for the current process.
