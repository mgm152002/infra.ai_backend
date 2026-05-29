"""Tests for app.core.encryption module."""

import pytest
from unittest.mock import patch, MagicMock


class TestEncryption:
    """Test AES-GCM encryption/decryption via EncryptionService."""

    def test_encryption_service_importable(self):
        """EncryptionService should be importable."""
        from app.core.encryption import EncryptionService

        assert EncryptionService is not None

    def test_encryption_service_has_encrypt(self):
        """EncryptionService should have encrypt method."""
        from app.core.encryption import EncryptionService

        service = EncryptionService()
        assert hasattr(service, "encrypt")

    def test_encryption_service_has_decrypt(self):
        """EncryptionService should have decrypt method."""
        from app.core.encryption import EncryptionService

        service = EncryptionService()
        assert hasattr(service, "decrypt")

    def test_encrypt_decrypt_roundtrip(self):
        """Encrypted data should decrypt back to original plaintext."""
        from app.core.encryption import EncryptionService

        service = EncryptionService()

        plaintext = "my-secret-api-key-12345"
        encrypted = service.encrypt(plaintext)

        assert encrypted != plaintext
        assert isinstance(encrypted, str)

        decrypted = service.decrypt(encrypted)
        assert decrypted == plaintext

    def test_encrypt_different_outputs(self):
        """Same plaintext should produce different ciphertexts (random nonce)."""
        from app.core.encryption import EncryptionService

        service = EncryptionService()

        plaintext = "same-secret"
        encrypted1 = service.encrypt(plaintext)
        encrypted2 = service.encrypt(plaintext)

        assert encrypted1 != encrypted2

    def test_encrypt_empty_string(self):
        """Encrypting empty string should work."""
        from app.core.encryption import EncryptionService

        service = EncryptionService()

        encrypted = service.encrypt("")
        decrypted = service.decrypt(encrypted)
        assert decrypted == ""

    def test_decrypt_invalid_data_raises(self):
        """Decrypting invalid data should raise an exception."""
        from app.core.encryption import EncryptionService

        service = EncryptionService()

        with pytest.raises(Exception):
            service.decrypt("not-valid-encrypted-data")

    def test_encrypt_unicode(self):
        """Should handle unicode characters."""
        from app.core.encryption import EncryptionService

        service = EncryptionService()

        plaintext = "secreto con acentos: áéíóú and 日本語"
        encrypted = service.encrypt(plaintext)
        decrypted = service.decrypt(encrypted)
        assert decrypted == plaintext
