import argparse
import json
import logging
import sys
from .core import decode_from_image_path # Relative import

# Logger for the CLI module. It will be configured by basicConfig in main_cli.
logger = logging.getLogger(__name__)

def main_cli():
    parser = argparse.ArgumentParser(
        prog="keylock-decode", # Program name for help messages
        description="Decode steganographically hidden, encrypted data from a PNG image.",
        epilog="Example: keylock-decode secret.png mypassword -o out.json --set-env",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("image_path", metavar="IMAGE_PATH", help="Path to the stego PNG image file.")
    parser.add_argument("password", metavar="PASSWORD", help="Password used for decryption.")
    parser.add_argument(
        "--set-env", 
        action="store_true", 
        help="Set decoded key-value pairs as environment variables for the current process. "
             "WARNING: This can be a security risk if the input image or password is untrusted."
    )
    parser.add_argument(
        "-o", "--output-file", 
        metavar="FILE",
        help="Optional path to save the decoded JSON data to a file."
    )
    parser.add_argument(
        "-v", "--verbose", 
        action="store_true", 
        help="Enable verbose debug logging for the library and CLI."
    )
    parser.add_argument(
        "--version",
        action="version",
        # Fetches version from __init__.py; requires a bit more setup if __init__ isn't imported early.
        # For simplicity here, hardcode or read from a common place.
        # A better way is to use importlib.metadata if Python 3.8+
        version=f"%(prog)s {__import__('keylock_decode').__version__}"
    )


    args = parser.parse_args()

    # Configure logging for the entire application (including library calls)
    log_level = logging.DEBUG if args.verbose else logging.INFO
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    # Using basicConfig on the root logger.
    # If the library's __init__ already set a handler, this might add another one
    # or be ignored if the root logger already has handlers.
    # For robust library logging, the library should only add NullHandler,
    # and the application (this CLI) configures the actual handlers.
    logging.basicConfig(level=log_level, format=log_format, stream=sys.stdout)
    
    logger.info("KeyLock-Decode CLI started.") # This uses the logger configured by basicConfig.
    if args.verbose:
        logger.debug("Verbose logging enabled.")

    if args.set_env:
        # This warning is critical and should be prominent.
        warning_msg = "SECURITY WARNING: --set-env flag is active. Decoded data will be attempted to be set as environment variables."
        logger.warning(warning_msg)
        print(warning_msg, file=sys.stderr) # Also print to stderr for visibility

    try:
        decoded_data, status_messages = decode_from_image_path(
            args.image_path, 
            args.password, 
            set_environment_variables=args.set_env
        )

        print("\n--- Status Messages ---")
        for msg in status_messages:
            print(f"[STATUS] {msg}") # Prefix status messages for clarity
        print("-----------------------")

        # Output decoded data regardless of whether it's empty, unless an error prevented its creation
        pretty_json_output = json.dumps(decoded_data, indent=2)
        print("\n--- Decoded Data ---")
        print(pretty_json_output)
        print("--------------------")

        if args.output_file:
            try:
                with open(args.output_file, 'w', encoding='utf-8') as f:
                    f.write(pretty_json_output)
                logger.info(f"Decoded data saved to: {args.output_file}")
                print(f"\n[INFO] Decoded data also saved to: {args.output_file}")
            except IOError as e:
                logger.error(f"Could not write to output file '{args.output_file}': {e}")
                print(f"Error: Could not write to output file '{args.output_file}': {e}", file=sys.stderr)
        
        logger.info("KeyLock-Decode CLI finished successfully.")
        sys.exit(0)

    except FileNotFoundError:
        logger.error(f"Input image file not found: {args.image_path}")
        print(f"Error: Input image file not found at '{args.image_path}'", file=sys.stderr)
        sys.exit(2) # Specific exit code for file not found
    except (ValueError, IOError) as e: 
        # Catches errors from core (bad password, corrupted, JSON format, PIL issues)
        logger.error(f"A processing error occurred: {e}")
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1) # General error exit code
    except Exception as e:
        logger.critical(f"An unexpected critical error occurred: {e}", exc_info=True)
        print(f"An unexpected critical error occurred. Check logs or run with -v for details: {e}", file=sys.stderr)
        sys.exit(3) # Specific exit code for unexpected errors

if __name__ == "__main__":
    main_cli()
