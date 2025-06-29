package EncryptDecrypt;

import java.security.Key;
import java.security.spec.KeySpec;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64; // Using Apache Commons Codec for Base64 operations

/**
 * A utility class for performing AES encryption and decryption using PBKDF2 for key derivation.
 * It uses AES in CBC (Cipher Block Chaining) mode with PKCS5Padding.
 *
 * IMPORTANT: Hardcoding IV, PASSWORD, and SALT is highly discouraged for production environments.
 * These values should be securely managed, e.g., through environment variables,
 * configuration management systems, or a secure key vault.
 */
public class crypt {

    // Initialization Vector (IV) - must be 16 bytes for AES.
    // This IV is static, which can be a security risk if not managed carefully.
    // For enhanced security, a unique IV should be generated for each encryption operation
    // and transmitted along with the ciphertext.
    private static String IV = "****************"; // Placeholder: Replace with a secure, randomly generated 16-byte IV.

    // Password for key derivation - used with PBKDF2.
    // This is the passphrase from which the actual encryption key is derived.
    private static String PASSWORD = "****************"; // Placeholder: Replace with a strong, securely managed password.

    // Salt for key derivation - used with PBKDF2.
    // The salt adds randomness to the key derivation process, making rainbow table attacks difficult.
    // A unique salt should be used per user or context.
    private static String SALT = "****************"; // Placeholder: Replace with a strong, securely managed salt.

    /**
     * Sets the salt value used for key derivation.
     * @param SALTvalue The new salt string.
     */
    public void setSalt(String SALTvalue) {
        crypt.SALT = SALTvalue;
    }

    /**
     * Resets the password to its default placeholder value.
     * This method might be used for development/testing but should be avoided in production.
     */
    public void setDefaultKey() {
        crypt.PASSWORD = "PASSWORD_VALUE"; // Resetting to original placeholder for demonstration.
    }

    /**
     * Encrypts a raw string and then encodes the resulting ciphertext in Base64.
     * Uses AES/CBC/PKCS5Padding.
     * @param raw The plain text string to be encrypted.
     * @return A Base64 encoded string of the encrypted data.
     * @throws RuntimeException if any cryptographic operation fails.
     */
    public String encryptAndEncode(String raw) {
        try {
            // Get a Cipher instance initialized for encryption mode.
            Cipher c = getCipher(Cipher.ENCRYPT_MODE);
            // Encrypt the raw string bytes (UTF-8)
            byte[] encryptedVal = c.doFinal(raw.getBytes("UTF-8"));
            // Base64 encode the encrypted bytes and return as a UTF-8 string.
            return new String(Base64.encodeBase64(encryptedVal), "UTF-8");
        } catch (Throwable t) {
            // Wrap any exception in a RuntimeException for simpler error propagation.
            // In a production app, proper logging and specific exception handling is recommended.
            throw new RuntimeException("Encryption failed: " + t.getMessage(), t);
        }
    }

    /**
     * Decodes a Base64 encoded encrypted string and then decrypts it.
     * Uses AES/CBC/PKCS5Padding.
     * @param encrypted The Base64 encoded encrypted string.
     * @return The decrypted plain text string.
     * @throws Exception if any cryptographic operation fails (e.g., incorrect padding, bad key).
     */
    public String decodeAndDecrypt(String encrypted) throws Exception {
        // Decode the Base64 string back to byte array.
        byte[] decodedValue = Base64.decodeBase64(encrypted.getBytes("UTF-8"));
        // Get a Cipher instance initialized for decryption mode.
        Cipher c = getCipher(Cipher.DECRYPT_MODE);
        // Decrypt the decoded bytes.
        byte[] decValue = c.doFinal(decodedValue);
        // Convert the decrypted bytes back to a UTF-8 string.
        return new String(decValue);
    }

    /**
     * Helper method to get and initialize a Cipher instance.
     * @param mode The cipher mode (Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE).
     * @return An initialized Cipher instance.
     * @throws Exception if Cipher initialization fails.
     */
    private static Cipher getCipher(int mode) throws Exception {
        // Get an AES Cipher instance with CBC mode and PKCS5Padding.
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        // Get IV bytes from the static IV string.
        byte[] iv = IV.getBytes("UTF-8");
        // Initialize the cipher with the specified mode, derived key, and IV.
        c.init(mode, generateKey(), new IvParameterSpec(iv));
        return c;
    }

    /**
     * Helper method to generate the AES encryption key using PBKDF2WithHmacSHA1.
     * This ensures that the key is derived securely from the password and salt.
     * @return The generated SecretKey.
     * @throws Exception if key generation fails.
     */
    private static Key generateKey() throws Exception {
        // Obtain a SecretKeyFactory for PBKDF2WithHmacSHA1.
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        // Convert password and salt strings to char and byte arrays, respectively.
        char[] password = PASSWORD.toCharArray();
        byte[] salt = SALT.getBytes("UTF-8");
        // Define key specification: password, salt, iteration count (65536 for strong derivation), key length (128 bits for AES-128).
        KeySpec spec = new PBEKeySpec(password, salt, 65536, 128);
        // Generate the secret key from the specification.
        SecretKey tmp = factory.generateSecret(spec);
        // Convert the derived key to an AES-specific SecretKeySpec.
        byte[] encoded = tmp.getEncoded();
        return new SecretKeySpec(encoded, "AES");
    }
}
