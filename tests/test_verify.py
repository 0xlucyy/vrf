import pytest
from VRF import (
    verify
)


class TestVerify:
    """
    This class contains unit tests for the `verify` function in the VRF module.
    """

    # Tests that the function returns True when all inputs are valid and the proof is valid.
    def test_valid_proof(self):
      """
      Test Case: Valid Proof Verification
      Description:
      - This test verifies that the `verify` function returns True when provided with valid inputs and a valid proof.
      - It uses a known valid public key, alpha, beta, proof, initial hash, salt, and revolver size.
      - The expected outcome is that the function should return True.
      """
      public_key = b'''-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE6RShk7NypzopzFyS0J7+scZ8MYvPo3Qa
RDk5GWNkkivoZeC7i0kyuEbz+JoBTJXbeZE8fN/K6rzeKTbN0upLow==
-----END PUBLIC KEY-----'''
      alpha = b'169411500630000300003000030000'
      beta = '30f809a17bc6e9e9fafd7c6b88df6b8497d2b156f4dedb5804aaa95d952d9484'
      proof = bytes.fromhex('24c3a12aa1033a9eca20a2a797cc838197336e73af5d2731f6343346d211d4a31daac377f1e3f9acd5f21e5126910a1083ee70578596b3a6a1d03b48d7cb8b56')
      initial_hash = 'f9d9cded83d076142fabe2eb442cd801d30ccebffaa1617c347ce4449e3747ff'
      salt = '6dcae08e5b89c2547058bc4df0d06f8db82e4fdf76777c9672872d5b3d144761'
      revolver_size = 50

      # Verification
      result = verify(public_key, alpha, beta, proof, initial_hash, salt, revolver_size)
      assert result == True


    # Tests that the function returns False when the proof is invalid.
    def test_invalid_proof(self):
        """
        Test Case: Invalid Proof Verification
        Description:
        - This test checks the behavior of the `verify` function when provided with an invalid proof.
        - It uses a different public key to make the proof invalid.
        - The expected outcome is that the function should return False.
        """
        public_key = b'''-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEZ+UfjF0JYsUOjPp0vKt1tiHtlos53okp
1nYv6rOfWExVZHN+fUCoIguneVzhN4o8qmZxU51kDQFuSEQ5wEfsfg==
-----END PUBLIC KEY-----'''
        alpha = b'169411500630000300003000030000'
        beta = '30f809a17bc6e9e9fafd7c6b88df6b8497d2b156f4dedb5804aaa95d952d9484'
        proof = bytes.fromhex('24c3a12aa1033a9eca20a2a797cc838197336e73af5d2731f6343346d211d4a31daac377f1e3f9acd5f21e5126910a1083ee70578596b3a6a1d03b48d7cb8b56')
        initial_hash = 'f9d9cded83d076142fabe2eb442cd801d30ccebffaa1617c347ce4449e3747ff'
        salt = '6dcae08e5b89c2547058bc4df0d06f8db82e4fdf76777c9672872d5b3d144761'
        revolver_size = 50

        # Verification
        result = verify(public_key, alpha, beta, proof, initial_hash, salt, revolver_size)
        assert result == False

    # Tests that the function returns False when the public key is invalid.
    def test_invalid_public_key(self, caplog):
      """
      Test Case: Invalid Public Key Verification
      Description:
      - This test checks the behavior of the `verify` function when provided with an invalid public key.
      - The public key is intentionally set to an integer to make it invalid.
      - The expected outcome is that the function should return False and log the appropriate error message.
      """
      # Values from the provided stdout
      public_key = 111111111111111111
      alpha = b'169411500630000300003000030000'
      beta = '30f809a17bc6e9e9fafd7c6b88df6b8497d2b156f4dedb5804aaa95d952d9484'
      proof = bytes.fromhex('24c3a12aa1033a9eca20a2a797cc838197336e73af5d2731f6343346d211d4a31daac377f1e3f9acd5f21e5126910a1083ee70578596b3a6a1d03b48d7cb8b56')
      initial_hash = 'f9d9cded83d076142fabe2eb442cd801d30ccebffaa1617c347ce4449e3747ff'
      salt = '6dcae08e5b89c2547058bc4df0d06f8db82e4fdf76777c9672872d5b3d144761'
      revolver_size = 50

      # with pytest.raises(ValueError):

      # Verification
      result = verify(public_key, alpha, beta, proof, initial_hash, salt, revolver_size)
      assert result == False
      assert "Verification of the proof failed: 'int' object has no attribute 'split'" == caplog.messages[0]


    # Tests that the function returns False when the alpha is invalid.
    def test_invalid_alpha(self, caplog):
      """
      Test Case: Invalid Alpha Verification
      Description:
      - This test checks the behavior of the `verify` function when provided with an invalid alpha value.
      - The alpha value is intentionally set to an invalid string.
      - The expected outcome is that the function should return False and log the appropriate error message.
      """
      public_key = b'''-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE6RShk7NypzopzFyS0J7+scZ8MYvPo3Qa
RDk5GWNkkivoZeC7i0kyuEbz+JoBTJXbeZE8fN/K6rzeKTbN0upLow==
-----END PUBLIC KEY-----'''
      alpha = b'INVALID'
      beta = '30f809a17bc6e9e9fafd7c6b88df6b8497d2b156f4dedb5804aaa95d952d9484'
      proof = bytes.fromhex('24c3a12aa1033a9eca20a2a797cc838197336e73af5d2731f6343346d211d4a31daac377f1e3f9acd5f21e5126910a1083ee70578596b3a6a1d03b48d7cb8b56')
      initial_hash = 'f9d9cded83d076142fabe2eb442cd801d30ccebffaa1617c347ce4449e3747ff'
      salt = '6dcae08e5b89c2547058bc4df0d06f8db82e4fdf76777c9672872d5b3d144761'
      revolver_size = 50

      # Verification
      result = verify(public_key, alpha, beta, proof, initial_hash, salt, revolver_size)
      assert result == False
      assert 'Verification of the proof failed: Signature verification failed' == caplog.messages[0]

