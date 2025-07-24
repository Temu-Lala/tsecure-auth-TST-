import sys
import json
from tsecure_auth.core.security import TSTCipher
from tsecure_auth.exceptions import InvalidTokenError

# IMPORTANT: This key MUST match the one in your main.py file.
# In a real application, you would load this from the same secure source.
ENCRYPTION_KEY = "a_super_secret_and_long_enough_key_for_aes_256_gcm"

def decrypt_token(token_string: str):
    """
    A simple command-line tool to decrypt a TST and print its contents.
    """
    print("--- TST Decryption Tool ---")
    
    if not token_string:
        print("Error: Please provide a token to decrypt.")
        print("Usage: python decrypt_tool.py <your_tst_token>")
        return

    try:
        cipher = TSTCipher(ENCRYPTION_KEY)
        payload = cipher.decrypt(token_string.encode('utf-8'))
        
        print("\n[✅] Token Decrypted Successfully!")
        print("\n--- Payload Contents ---")
        print(json.dumps(payload, indent=2))
        print("------------------------")

    except InvalidTokenError as e:
        print(f"\n[❌] ERROR: Could not decrypt token. It may be invalid, tampered with, or encrypted with a different key.")
        print(f"    Details: {e}")
    except Exception as e:
        print(f"\n[❌] An unexpected error occurred: {e}")


if __name__ == "__main__":
    # Get the token from the command line arguments
    token_to_decrypt = sys.argv[1] if len(sys.argv) > 1 else None
    decrypt_token(token_to_decrypt)
