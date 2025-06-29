import base64
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

class PKCS7Encoder:
    def __init__(self, block_size=AES.block_size):
        self.block_size = block_size

    def encode(self, text):
        # Pad the text to be a multiple of the block_size
        pad_len = self.block_size - (len(text) % self.block_size)
        padding = bytes([pad_len]) * pad_len
        return text.encode('utf-8') + padding

    def decode(self, padded_text):
        # Remove PKCS7 padding from the text
        pad_len = padded_text[-1]
        return padded_text[:-pad_len].decode('utf-8')


class Crypt:
    """
    A utility class for performing AES encryption and decryption using PBKDF2 for key derivation.
    It uses AES in CBC (Cipher Block Chaining) mode with PKCS7Padding.

    IMPORTANT: Hardcoding IV, PASSWORD_VALUE, and SALT_VALUE is highly discouraged for
    production environments. These values should be securely managed, e.g., through
    environment variables, configuration management systems, or a secure key vault.
    """

    # Password for key derivation - used with PBKDF2.
    # This is the passphrase from which the actual encryption key is derived.
    PASSWORD_VALUE = '****************' # Placeholder: Replace with a strong, securely managed password.

    # Salt for key derivation - used with PBKDF2.
    # The salt adds randomness to the key derivation process, making rainbow table attacks difficult.
    # A unique salt should be used per user or context.
    SALT_VALUE = '****************' # Placeholder: Replace with a strong, securely managed salt.

    # Initialization Vector (IV) - must be 16 bytes for AES.
    # This IV is static, which can be a security risk if not managed carefully.
    # For enhanced security, a unique IV should be generated for each encryption operation
    # and transmitted along with the ciphertext.
    IV_VALUE_16_BYTE = '****************' # Placeholder: Replace with a secure, randomly generated 16-byte IV.

    def EncryptStringAes(self, rawString, salt=""):
        """
        Encrypts a raw string using AES and then encodes the resulting ciphertext in Base64.
        Uses AES/CBC with PKCS7 padding.

        :param rawString: The plain text string to be encrypted.
        :param salt: The salt value for key derivation. Uses default if not provided.
                     For production, always provide a unique and securely managed salt.
        :return: A Base64 encoded string of the encrypted data, or an empty string on error.
        """
        try:
            # Determine the key to use (with provided salt or default salt)
            if salt == "":
                key = self.__getKey()
            else:
                key = self.__getKey(salt)

            if key == "":
                # Key derivation failed or returned empty.
                print("Error: Could not derive encryption key.")
                return ""

            # Create an AES cipher object in CBC mode with the derived key and IV.
            # IV_VALUE_16_BYTE is converted to bytes.
            aes_encrypter = AES.new(key, AES.MODE_CBC, bytes(self.IV_VALUE_16_BYTE, 'utf-8'))

            # Pad the raw string using PKCS7 before encryption.
            padded_raw_bytes = PKCS7Encoder().encode(rawString)

            # Encrypt the padded bytes and then Base64 encode the result.
            cipher_text = base64.b64encode(aes_encrypter.encrypt(padded_raw_bytes))
            return cipher_text.decode('utf-8') # Return as a UTF-8 string for consistency.

        except Exception as ex:
            # Catch any exceptions during the process and print them.
            # In a production app, proper logging and specific exception handling is recommended.
            print(f"Encryption failed: {ex}")
            return ""

    def DecryptStringAes(self, encryptedString, salt=""):
        """
        Decodes a Base64 encoded encrypted string and then decrypts it using AES.
        Uses AES/CBC with PKCS7 padding.

        :param encryptedString: The Base64 encoded encrypted string.
        :param salt: The salt value for key derivation. Uses default if not provided.
        :return: The decrypted plain text string, or an empty string on error.
        """
        try:
            # Determine the key to use (with provided salt or default salt)
            if salt == "":
                key = self.__getKey()
            else:
                key = self.__getKey(salt)

            if key == "":
                # Key derivation failed or returned empty.
                print("Error: Could not derive decryption key.")
                return ""

            # Create an AES cipher object in CBC mode with the derived key and IV.
            aes_decrypter = AES.new(key, AES.MODE_CBC, bytes(self.IV_VALUE_16_BYTE, 'utf-8'))

            # Base64 decode the encrypted string.
            decoded_encrypted_bytes = base64.b64decode(encryptedString)

            # Decrypt the decoded bytes.
            decrypted_padded_bytes = aes_decrypter.decrypt(decoded_encrypted_bytes)

            # Remove PKCS7 padding and decode to UTF-8 string.
            clear_text = PKCS7Encoder().decode(decrypted_padded_bytes)
            return clear_text

        except Exception as ex:
            # Catch any exceptions during the process and print them.
            print(f"Decryption failed: {ex}")
            return ""

    def __getKey(self, inputsalt=SALT_VALUE):
        """
        Helper method to generate the AES encryption key using PBKDF2HMAC (SHA1).
        This ensures that the key is derived securely from the password and salt.

        :param inputsalt: The salt string to use for key derivation.
        :return: The derived encryption key as bytes, or an empty string on error.
        """
        try:
            # Use the default cryptography backend.
            backend = default_backend()
            # Convert salt and password to bytes.
            salt_bytes = bytes(inputsalt, 'utf-8')
            password_bytes = bytes(self.PASSWORD_VALUE, 'utf-8')

            # Initialize PBKDF2HMAC with SHA1 algorithm, 16-byte key length, salt, and iteration count.
            # Iteration count (65536) is a commonly recommended value for security.
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA1(),
                length=16, # 16 bytes = 128 bits for AES-128
                salt=salt_bytes,
                iterations=65536,
                backend=backend
            )
            # Derive the key from the password.
            key = kdf.derive(password_bytes)
            return key
        except Exception as ex:
            print(f"Key derivation failed: {ex}")
            return ""

