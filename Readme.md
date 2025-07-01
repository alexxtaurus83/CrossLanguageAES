Here's the Markdown version of your text.

## Overview 🛡️
This project is an experiment in cross-language string encryption, providing a set of utility classes in `Java`, `C#`, and `Python` for `AES` encryption and decryption. An `Angular` component is also included but has not been tested yet.

All implementations use `AES` in `CBC` mode with `PKCS7` (or the compatible `PKCS5` in `Java`) padding. Keys are derived from a password using the `PBKDF2` algorithm with `HMAC-SHA1`.

---
## Interoperability Requirements 🔑
For successful encryption and decryption across languages, the following **critical parameters** must be **identical** in every implementation:

* **AES Key Length**: 128-bit
* **Mode**: `CBC` (Cipher Block Chaining)
* **Padding**: `PKCS7`
* **PBKDF2 Iterations**: 65,536
* **Password**: The secret password used for key derivation.
* **Salt**: The salt used with the password for key derivation.
* **IV (Initialization Vector)**: Must be 16 bytes (128 bits).