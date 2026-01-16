import os
import base64
from app.core.config import settings
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class EncryptionService:
    """
    Service for encrypting and decrypting sensitive data (like SSH keys)
    using AES-GCM (Galois/Counter Mode).
    """
    def __init__(self):
        # Ensure we have a valid key. The key must be 16, 24, or 32 bytes.
        # We derive it from settings or use a default (NOT SECURE for production if default is used)
        # In production, SETTINGS.ENCRYPTION_KEY should be a base64 encoded 32-byte key.
        self.key = self._get_key()
        self.aesgcm = AESGCM(self.key)

    def _get_key(self) -> bytes:
        """Retrieve and validate the KEK (Key Encryption Key)."""
        env_key = getattr(settings, "ENCRYPTION_KEY", None)
        if env_key:
            try:
                decoded_key = base64.b64decode(env_key)
                if len(decoded_key) not in (16, 24, 32):
                     raise ValueError("Key length must be 16, 24, or 32 bytes")
                return decoded_key
            except Exception as e:
                # Log error in production
                print(f"Invalid encryption key provided: {e}")

        # Fallback/Dev key (Deterministic for local dev, avoid in prod)
        # 32 bytes
        return b"0" * 32

    def encrypt(self, plain_text: str) -> str:
        """
        Encrypts a string and returns a base64 encoded ciphertext (including nonce).
        Format: nonce + ciphertext
        """
        if not plain_text:
            return ""
        
        nonce = os.urandom(12) # GCM standard nonce size
        data = plain_text.encode("utf-8")
        ciphertext = self.aesgcm.encrypt(nonce, data, None)
        
        # Combine nonce + ciphertext and base64 encode
        return base64.b64encode(nonce + ciphertext).decode("utf-8")

    def decrypt(self, encrypted_text: str) -> str:
        """
        Decrypts a base64 encoded ciphertext string.
        """
        if not encrypted_text:
            return ""

        try:
            raw_data = base64.b64decode(encrypted_text.encode("utf-8"))
            if len(raw_data) < 12:
                raise ValueError("Invalid ciphertext length")
            
            nonce = raw_data[:12]
            ciphertext = raw_data[12:]
            
            plaintext = self.aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext.decode("utf-8")
        except Exception as e:
            # Handle decryption failure (log it)
            print(f"Decryption failed: {e}")
            raise ValueError("Decryption failed")

# Global instance
encryption_service = EncryptionService()
