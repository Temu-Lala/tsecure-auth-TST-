import os
import json
import base64
import uuid
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ..exceptions import InvalidTokenError

class TSTCipher:
    """
    Handles the end-to-end encryption and decryption of TST (Temesgen Secure Token) payloads.
    Uses AES-256-GCM for authenticated encryption, which provides both confidentiality and integrity.
    """

    def __init__(self, encryption_key: str):
        """
        Initializes the cipher with a 32-byte key.
        Args:
            encryption_key: A secret key for encryption. Must be at least 32 characters.
        Raises:
            ValueError: If the key is not 32 bytes long.
        """
        if len(encryption_key.encode('utf-8')) < 32:
            raise ValueError("Encryption key must be at least 32 bytes long.")
        
        # In a production system, consider using a key derivation function (KDF) like PBKDF2
        # or HKDF to derive the key, but for simplicity, we'll use the provided key directly.
        self.key = encryption_key.encode('utf-8')[:32]
        self.aesgcm = AESGCM(self.key)

    def encrypt(self, payload: dict) -> bytes:
        """
        Encrypts a JSON payload.
        1. Serializes the payload dictionary to a JSON string.
        2. Generates a random 96-bit (12-byte) nonce for each encryption operation. This is critical for security.
        3. Encrypts the payload using AES-GCM.
        4. Returns the nonce concatenated with the ciphertext, encoded in URL-safe Base64.
        """
        nonce = os.urandom(12)
        payload_bytes = json.dumps(payload, default=str).encode('utf-8')
        ciphertext = self.aesgcm.encrypt(nonce, payload_bytes, None)
        return base64.urlsafe_b64encode(nonce + ciphertext)

    def decrypt(self, encrypted_token: bytes) -> dict:
        """
        Decrypts a TST token.
        1. Base64-decodes the token.
        2. Extracts the nonce (first 12 bytes) and the ciphertext.
        3. Decrypts the ciphertext using AES-GCM. AES-GCM automatically verifies the integrity.
        4. Deserializes the JSON string back into a dictionary.
        Returns:
            The decrypted payload dictionary.
        Raises:
            InvalidTokenError: If the token is malformed, has been tampered with, or if the decryption key is incorrect.
        """
        try:
            token_bytes = base64.urlsafe_b64decode(encrypted_token)
            if len(token_bytes) < 13:
                raise InvalidTokenError("Invalid token format.")
                
            nonce = token_bytes[:12]
            ciphertext = token_bytes[12:]
            
            decrypted_bytes = self.aesgcm.decrypt(nonce, ciphertext, None)
            return json.loads(decrypted_bytes.decode('utf-8'))
        except Exception as e:
            raise InvalidTokenError("Token is invalid or has been tampered with.") from e


def create_token(
    token_type: str,
    data: dict,
    cipher: TSTCipher,
    expires_delta: timedelta,
) -> str:
    """
    Creates a TST of a specific type (e.g., 'access' or 'refresh') with an expiration claim.
    
    Args:
        token_type: The type of token ('access' or 'refresh').
        data: The payload to store in the token.
        cipher: An instance of TSTCipher to perform encryption.
        expires_delta: The lifetime of the token.
    
    Returns:
        An encrypted, Base64-encoded TST string.
    """
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    expire = now + expires_delta
    to_encode.update({
        "exp": expire.isoformat(),
        "iat": now.isoformat(),
        "jti": str(uuid.uuid4()), # Unique ID for this token, for revocation
        "type": token_type,
    })
    encrypted_token = cipher.encrypt(to_encode)
    return encrypted_token.decode('utf-8')


def verify_token(token: str, cipher: TSTCipher, expected_type: str = "access") -> dict:
    """
    Verifies a TST access token. It checks the signature and the expiration time.
    
    Args:
        token: The TST string to verify.
        cipher: An instance of TSTCipher to perform decryption.
        
    Returns:
        The token's payload if it is valid.
        
    Raises:
        InvalidTokenError: If the token is expired or otherwise invalid.
    """
    payload = cipher.decrypt(token.encode('utf-8'))
    
    exp_str = payload.get("exp")
    if not exp_str:
        raise InvalidTokenError("Token is missing the 'exp' claim.")
        
    exp_time = datetime.fromisoformat(exp_str)
    if exp_time < datetime.now(timezone.utc):
        raise InvalidTokenError("Token has expired.")

    token_type = payload.get("type")
    if token_type != expected_type:
        raise InvalidTokenError(f"Invalid token type: expected '{expected_type}', got '{token_type}'.")
        
    return payload
