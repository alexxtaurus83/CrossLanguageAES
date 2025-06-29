// npm install crypto-js @types/crypto-js
import { Injectable } from '@angular/core';
import * as CryptoJS from 'crypto-js';

@Injectable({
  providedIn: 'root'
})
export class EncryptionService {

  // IMPORTANT: Hardcoding IV, PASSWORD, and SALT is highly discouraged for production environments.
  // These values should be securely managed, e.g., through environment variables,
  // configuration management systems, or a secure key vault.

  // Initialization Vector (IV) - must be 16 bytes for AES.
  // This IV is static, which can be a security risk if not managed carefully.
  // For enhanced security, a unique IV should be generated for each encryption operation
  // and transmitted along with the ciphertext.
  private static IV: string = "****************"; // Placeholder: Replace with a secure, randomly generated 16-byte IV.

  // Password for key derivation - used with PBKDF2.
  // This is the passphrase from which the actual encryption key is derived.
  private static PASSWORD: string = "****************"; // Placeholder: Replace with a strong, securely managed password.

  // Salt for key derivation - used with PBKDF2.
  // The salt adds randomness to the key derivation process, making rainbow table attacks difficult.
  // A unique salt should be used per user or context.
  private static SALT: string = "****************"; // Placeholder: Replace with a strong, securely managed salt.

  constructor() { }

  /**
   * Sets the salt value used for key derivation.
   * @param SALTvalue The new salt string.
   */
  setSalt(SALTvalue: string): void {
    EncryptionService.SALT = SALTvalue;
  }

  /**
   * Resets the password to its default placeholder value.
   * This method might be used for development/testing but should be avoided in production.
   */
  setDefaultKey(): void {
    EncryptionService.PASSWORD = "PASSWORD_VALUE"; // Resetting to original placeholder for demonstration.
  }

  /**
   * Encrypts a raw string using AES and then encodes the resulting ciphertext in Base64.
   * Uses AES/CBC/PKCS7Padding.
   * @param raw The plain text string to be encrypted.
   * @return A Base64 encoded string of the encrypted data.
   */
  encryptAndEncode(raw: string): string {
    try {
      const key = this.generateKey();
      const iv = CryptoJS.enc.Utf8.parse(EncryptionService.IV);

      const encrypted = CryptoJS.AES.encrypt(raw, key, {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7, // PKCS7Padding is equivalent to PKCS5Padding for AES block sizes
        hasher: CryptoJS.algo.SHA1, // Specify SHA1 for PBKDF2
        iterations: 65536 // Number of iterations for PBKDF2
      });

      return encrypted.toString(); // Already Base64 encoded by crypto-js
    } catch (error) {
      console.error("Encryption failed:", error);
      throw new Error(`Encryption failed: ${error}`);
    }
  }

  /**
   * Decodes a Base64 encoded encrypted string and then decrypts it.
   * Uses AES/CBC/PKCS7Padding.
   * @param encrypted The Base64 encoded encrypted string.
   * @return The decrypted plain text string.
   */
  decodeAndDecrypt(encrypted: string): string {
    try {
      const key = this.generateKey();
      const iv = CryptoJS.enc.Utf8.parse(EncryptionService.IV);

      const decrypted = CryptoJS.AES.decrypt(encrypted, key, {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7, // PKCS7Padding is equivalent to PKCS5Padding for AES block sizes
        hasher: CryptoJS.algo.SHA1, // Specify SHA1 for PBKDF2
        iterations: 65536 // Number of iterations for PBKDF2
      });

      return decrypted.toString(CryptoJS.enc.Utf8);
    } catch (error) {
      console.error("Decryption failed:", error);
      throw new Error(`Decryption failed: ${error}`);
    }
  }

  /**
   * Helper method to generate the AES encryption key using PBKDF2 with HMAC-SHA1.
   * This ensures that the key is derived securely from the password and salt.
   * @return The generated WordArray representing the key.
   */
  private generateKey(): CryptoJS.lib.WordArray {
    // CryptoJS.PBKDF2 returns a WordArray, which is what CryptoJS.AES.encrypt expects as a key.
    return CryptoJS.PBKDF2(EncryptionService.PASSWORD, CryptoJS.enc.Utf8.parse(EncryptionService.SALT), {
      keySize: 128 / 8, // 128 bits / 8 bits per byte = 16 bytes
      iterations: 65536,
      hasher: CryptoJS.algo.SHA1 // Specify SHA1 for PBKDF2
    });
  }
}