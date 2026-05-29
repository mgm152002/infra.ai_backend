import sys
import os
import unittest

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from app.core.encryption import encryption_service, EncryptionService

class TestEncryption(unittest.TestCase):
    def test_encrypt_decrypt(self):
        original = "SSH-PRIVATE-KEY-SECRET-12345"
        encrypted = encryption_service.encrypt(original)
        print(f"Original: {original}")
        print(f"Encrypted: {encrypted}")
        
        self.assertNotEqual(original, encrypted)
        
        decrypted = encryption_service.decrypt(encrypted)
        print(f"Decrypted: {decrypted}")
        
        self.assertEqual(original, decrypted)

    def test_empty(self):
        self.assertEqual(encryption_service.encrypt(""), "")
        self.assertEqual(encryption_service.decrypt(""), "")

    def test_invalid_decrypt(self):
        with self.assertRaises(Exception):
            encryption_service.decrypt("invalid-base64")

if __name__ == "__main__":
    unittest.main()
