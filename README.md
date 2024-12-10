# 🔒 FastCrypt

[![Pub Version](https://img.shields.io/pub/v/fastcrypt)](https://pub.dev/packages/fastcrypt)
[![codecov](https://codecov.io/gh/jonataslaw/fastcrypt/graph/badge.svg?token=U4EJLE94VI)](https://codecov.io/gh/jonataslaw/fastcrypt)

**FastCrypt** is a high-performance, secure encryption library for Dart, leveraging the powerful **ChaCha20-Poly1305** algorithm. Designed with versatility in mind, FastCrypt can be seamlessly integrated into Dart applications across various platforms, ensuring your data remains confidential and tamper-proof. With a small code you have cutting-edge encryption in your hands:

```dart
final fastCrypt = FastCrypt();
// To encrypt a message
final encrypted = fastCrypt.encryptText('Top secret message');
// To decrypt the message
final decrypted = fastCrypt.decryptText(encrypted);
```

---

## 📚 Table of Contents

- [🔒 FastCrypt](#-fastcrypt)
  - [📚 Table of Contents](#-table-of-contents)
  - [📝 Introduction](#-introduction)
  - [🚀 Why FastCrypt?](#-why-fastcrypt)
    - [⚡ Superior Performance](#-superior-performance)
    - [🔐 Rock-Solid Security](#-rock-solid-security)
    - [👩‍💻 Developer-Friendly](#-developer-friendly)
  - [🔒 Cryptography Basics](#-cryptography-basics)
    - [🔑 Key](#-key)
    - [🔄 Nonce](#-nonce)
    - [📑 AAD (Additional Authenticated Data)](#-aad-additional-authenticated-data)
    - [🏷️ Tag](#️-tag)
    - [🔒 Ciphertext](#-ciphertext)
  - [🌟 Features](#-features)
  - [⚙️ Installation](#️-installation)
  - [🚀 Quick Start](#-quick-start)
    - [Encrypting and Decrypting Strings](#encrypting-and-decrypting-strings)
    - [Encrypting and Decrypting Bytes](#encrypting-and-decrypting-bytes)
    - [Generating Keys and Nonces](#generating-keys-and-nonces)
    - [Stream Transformers](#stream-transformers)
      - [`ChaCha20Poly1305Encryptor` Class](#chacha20poly1305encryptor-class)
      - [`ChaCha20Poly1305Decryptor` Class](#chacha20poly1305decryptor-class)
  - [🧩 Examples](#-examples)
    - [Encrypting a Message with AAD](#encrypting-a-message-with-aad)
      - [Usage with Streams](#usage-with-streams)
  - [📘 API Reference](#-api-reference)
    - [`FastCrypt` Class](#fastcrypt-class)
      - [Methods](#methods)
  - [🛡️ Security Considerations](#️-security-considerations)
  - [✅ Best Practices](#-best-practices)
  - [🤝 Contributing](#-contributing)
  - [📜 License](#-license)
  - [📚 References](#-references)

---

## 📝 Introduction

In the digital age, securing data is paramount. Whether you're developing mobile apps, web applications, or backend services in Dart, ensuring that sensitive information remains protected is crucial. **FastCrypt** offers a robust solution by implementing the ChaCha20 encryption algorithm combined with Poly1305 for authentication, providing both confidentiality and integrity for your data.

---

## 🚀 Why FastCrypt?

### ⚡ Superior Performance

- **Software-Optimized**: ChaCha20 outperforms AES on platforms without hardware acceleration
- **Cross-Platform Excellence**: Consistent high performance across mobile, web, and server
- **Pure Dart Implementation**: No native dependencies or platform-specific code

### 🔐 Rock-Solid Security

- **Modern Cryptography**: Based on the IETF standard RFC 8439
- **Complete Protection**: Combines encryption (ChaCha20) with authentication (Poly1305)
- **Battle-Tested**: Used in TLS 1.3 and trusted by major tech companies

### 👩‍💻 Developer-Friendly

- **Simple API**: Intuitive methods for both string and byte-based encryption
- **Comprehensive Documentation**: Clear examples and explanations
- **Built-in Safety**: Automatic key and nonce generation

---

## 🔒 Cryptography Basics

Before diving into using FastCrypt, it's essential to understand some fundamental cryptographic concepts. Don't worry—we'll break them down in simple terms!

### 🔑 Key

Think of the **key** as the secret password used to encrypt and decrypt your data. It should be kept confidential; anyone with access to the key can decrypt your data.

- **Length:** FastCrypt uses a **32-byte** (256-bit) key, providing a high level of security.

### 🔄 Nonce

A **nonce** (number used once) is a random value that ensures each encryption operation produces a unique ciphertext, even if the same plaintext and key are used multiple times.

- **Length:** FastCrypt uses a **12-byte** nonce.

### 📑 AAD (Additional Authenticated Data)

**AAD** allows you to include additional information that you'd like to authenticate but not encrypt. This data is verified during decryption to ensure it hasn't been tampered with.

- **Use Case:** Including headers or metadata alongside your encrypted data.

### 🏷️ Tag

The **tag** is a result of the authentication process. It ensures that the ciphertext hasn't been altered and that it originates from a trusted source.

- **Length:** FastCrypt generates a **16-byte** tag.

### 🔒 Ciphertext

**Ciphertext** is the encrypted version of your plaintext data. Without the correct key and nonce, it should be computationally infeasible to revert to the original plaintext.

---

## 🌟 Features

- **Authenticated Encryption:** Ensures both the confidentiality and integrity of your data.
- **Random Key and Nonce Generation:** Provides secure random generation methods for keys and nonces.
- **Flexible API:** Supports both string and byte data types for encryption and decryption.
- **Error Handling:** Throws specific exceptions (e.g., `AuthenticationException`) when authentication fails.
- **Lightweight:** No dependencies, ensuring your application remains lean.

---

## ⚙️ Installation

Add **FastCrypt** to your `pubspec.yaml`:

```yaml
dependencies:
  fastcrypt: ^1.0.0
```

Then, run:

```bash
flutter pub get
```

_Note: Replace `^1.0.0` with the latest version available._

---

## 🚀 Quick Start

### Encrypting and Decrypting Strings

Encrypting and decrypting text is straightforward with FastCrypt.

```dart
import 'package:fastcrypt/fastcrypt.dart';

void main() {
  final crypt = FastCrypt();

  String plaintext = "Hello, Dart!";

  // Encrypt the plaintext
  EncryptedData encrypted = crypt.encryptString(plaintext);

  print('Ciphertext: ${encrypted.ciphertext}');
  print('Tag: ${encrypted.tag}');
  print('Nonce: ${encrypted.nonce}');

  // Decrypt the ciphertext
  String decrypted = crypt.decryptString(
    ciphertext: encrypted.ciphertext,
    tag: encrypted.tag,
    key: encrypted.key,
    nonce: encrypted.nonce,
  );

  print('Decrypted Text: $decrypted');
}
```

### Encrypting and Decrypting Bytes

For binary data, use the byte-based methods.

```dart
import 'dart:convert';
import 'package:fastcrypt/fastcrypt.dart';

void main() {
  final crypt = FastCrypt();

  // Sample binary data
  List<int> data = utf8.encode("Binary Data Example");

  // Encrypt the data
  EncryptedData encrypted = crypt.encryptBytes(data);

  print('Ciphertext: ${encrypted.ciphertext}');
  print('Tag: ${encrypted.tag}');
  print('Nonce: ${encrypted.nonce}');

  // Decrypt the data
  List<int> decryptedBytes = crypt.decryptBytes(
    ciphertext: encrypted.ciphertext,
    tag: encrypted.tag,
    key: encrypted.key,
    nonce: encrypted.nonce,
  );

  String decrypted = utf8.decode(decryptedBytes);
  print('Decrypted Data: $decrypted');
}
```

### Generating Keys and Nonces

FastCrypt provides methods to generate a **key** and a **nonce** securely. The encrypt and decrypt methods can also generate these values if not provided.
If you prefer to generate them separately, you can use the following:

```dart
import 'package:fastcrypt/fastcrypt.dart';

void main() {
  // Generate a 32-byte key
  List<int> key = FastCrypt.generateKey();

  // Generate a 12-byte nonce
  List<int> nonce = FastCrypt.generateNonce();

  print('Key: $key');
  print('Nonce: $nonce');
}
```

I'll help you add documentation for the ChaCha20Poly1305Encryptor and ChaCha20Poly1305Decryptor classes to your README. Here's how you can include them in your API Reference section:

### Stream Transformers

#### `ChaCha20Poly1305Encryptor` Class

A stream transformer that encrypts data using ChaCha20-Poly1305, processing it in chunks for efficient memory usage.

```dart
final encryptor = ChaCha20Poly1305Encryptor(
  cipher: cipher,
  key: key,
  nonce: nonce,
  aad: aad,         // optional
  chunkSize: 64000, // optional, default is 64KB
);

// Use with a stream
final encryptedStream = inputStream.transform(encryptor);
```

- **Parameters:**

  - `cipher`: An instance of `ChaCha20Poly1305`
  - `key`: A 32-byte encryption key
  - `nonce`: A 12-byte nonce
  - `aad`: Optional additional authenticated data
  - `chunkSize`: Size of chunks to process (default: 64KB)

- **Output Stream Format:**
  1. Nonce (first chunk)
  2. Encrypted data chunks
  3. Authentication tag (final chunk)

#### `ChaCha20Poly1305Decryptor` Class

A stream transformer that decrypts data previously encrypted with ChaCha20-Poly1305.

```dart
final decryptor = ChaCha20Poly1305Decryptor(
  cipher: cipher,
  key: key,
  aad: aad,         // optional
  chunkSize: 64000, // optional, default is 64KB
);

// Use with a stream
final decryptedStream = inputStream.transform(decryptor);
```

- **Parameters:**

  - `cipher`: An instance of `ChaCha20Poly1305`
  - `key`: A 32-byte decryption key
  - `aad`: Optional additional authenticated data
  - `chunkSize`: Size of chunks to process (default: 64KB)

- **Input Stream Format:**

  - Expects data in the format output by `ChaCha20Poly1305Encryptor`
  - Must include nonce (first 12 bytes) and tag (last 16 bytes)

- **Throws:**
  - `AuthenticationException`: If the authentication tag verification fails
  - `StateError`: If the input stream is empty
  - `ArgumentError`: If the input data is too short to contain nonce and tag

---

## 🧩 Examples

### Encrypting a Message with AAD

Including **AAD** enhances security by binding additional data to the ciphertext.

```dart
import 'package:fastcrypt/fastcrypt.dart';

void main() {
  final crypt = FastCrypt();

  String message = "Sensitive Information";
  List<int> aad = utf8.encode("User ID: 12345");

  // Encrypt with AAD
  EncryptedData encrypted = crypt.encryptString(
    message,
    aad: aad,
  );

  print('Ciphertext: ${encrypted.ciphertext}');
  print('Tag: ${encrypted.tag}');
  print('Nonce: ${encrypted.nonce}');

  // Decrypt with AAD
  try {
    String decrypted = crypt.decryptString(
      ciphertext: encrypted.ciphertext,
      tag: encrypted.tag,
      key: encrypted.key,
      nonce: encrypted.nonce,
      aad: aad,
    );
    print('Decrypted Message: $decrypted');
  } catch (e) {
    print('Decryption failed: $e');
  }
}
```

_If the AAD provided during decryption doesn't match the one used during encryption, decryption will fail, ensuring data integrity._

#### Usage with Streams

```dart
import 'package:fastcrypt/fastcrypt.dart';

void main() async {
  final cipher = ChaCha20Poly1305();
  final key = FastCrypt.generateKey();
  final nonce = FastCrypt.generateNonce();

  // Create transformers
  final encryptor = ChaCha20Poly1305Encryptor(
    cipher: cipher,
    key: key,
    nonce: nonce,
  );

  final decryptor = ChaCha20Poly1305Decryptor(
    cipher: cipher,
    key: key,
  );

  // Example stream encryption and decryption
  final inputData = [1, 2, 3, 4, 5];
  final inputStream = Stream.fromIterable([inputData]);

  // Encrypt
  final encryptedStream = inputStream.transform(encryptor);
  final encryptedData = await encryptedStream.toList();

  // Decrypt
  final decryptStream = Stream.fromIterable(encryptedData)
      .transform(decryptor);
  final decryptedData = await decryptStream.toList();

  print('Decrypted: ${decryptedData.first}');
}
```

---

## 📘 API Reference

### `FastCrypt` Class

#### Methods

- **`generateKey()`**

  Generates a secure 32-byte random key.

  ```dart
  static List<int> generateKey();
  ```

- **`generateNonce()`**

  Generates a secure 12-byte random nonce.

  ```dart
  static List<int> generateNonce();
  ```

- **`encryptString(String plaintext, {List<int>? key, List<int>? nonce, List<int> aad = const []})`**

  Encrypts a plaintext string.

  - **Parameters:**

    - `plaintext`: The text to encrypt.
    - `key`: Optional 32-byte key. If not provided, a new key is generated.
    - `nonce`: Optional 12-byte nonce. If not provided, a new nonce is generated.
    - `aad`: Optional additional authenticated data.

  - **Returns:** `EncryptedData` object containing ciphertext, tag, and nonce.

- **`decryptString({required List<int> ciphertext, required List<int> tag, required List<int> key, required List<int> nonce, List<int> aad = const []})`**

  Decrypts ciphertext to retrieve the original string.

  - **Parameters:**

    - `ciphertext`: The encrypted data.
    - `tag`: The authentication tag.
    - `key`: The 32-byte key used during encryption.
    - `nonce`: The 12-byte nonce used during encryption.
    - `aad`: The same additional authenticated data used during encryption.

  - **Returns:** Decrypted plaintext string.

  - **Throws:** `AuthenticationException` if authentication fails.

- **`encryptBytes(List<int> plaintext, {List<int>? key, List<int>? nonce, List<int> aad = const []})`**

  Encrypts plaintext bytes.

  - **Parameters:** Same as `encryptString`.

  - **Returns:** `EncryptedData` object.

- **`decryptBytes({required List<int> ciphertext, required List<int> tag, required List<int> key, required List<int> nonce, List<int> aad = const []})`**

  Decrypts ciphertext bytes.

  - **Parameters:** Same as `decryptString`.

  - **Returns:** Decrypted plaintext bytes.

  - **Throws:** `AuthenticationException` if authentication fails.

---

## 🛡️ Security Considerations

- **Key Management:** Always store your encryption keys securely. Consider using secure storage solutions like the device's keychain or secure environment variables.
- **Nonce Uniqueness:** Never reuse a nonce with the same key. Reusing nonces can lead to vulnerabilities, potentially exposing your plaintext.
- **Authentication:** Always verify the **tag** during decryption to ensure the data's integrity and authenticity.
- **Randomness:** Utilize the provided key and nonce generation methods to ensure cryptographic randomness.
-

## ✅ Best Practices

1. **Never Reuse Keys or Nonces**

   ```dart
   // Good: Generate new values for each encryption
   final key = FastCrypt.generateKey();
   final nonce = FastCrypt.generateNonce();

   // Bad: Reusing values
   final reusedKey = savedKey; // Don't do this!
   ```

2. **Secure Key Storage**

   ```dart
   // Good: Use secure storage
   final storage = YourSecureStorage();
   await storage.write(key: 'encryption_key', value: key);

   // Bad: Storing in plain text
   SharedPreferences.setText('key', key); // Don't do this!
   ```

3. **Handle Errors Properly**
   ```dart
   try {
     final decrypted = fastCrypt.decryptString(...);
   } on AuthenticationException {
     // Handle tampering attempt
     logSecurityEvent('Data tampering detected');
   } catch (e) {
     // Handle other errors
     logError('Encryption error', e);
   }
   ```

---

## 🤝 Contributing

Contributions are welcome! Whether it's reporting a bug, suggesting a feature, or submitting a pull request, your involvement helps make FastCrypt better.

1. Fork the repository.
2. Create your feature branch: `git checkout -b feature/name`.
3. Commit your changes: `git commit -m 'Add some feature'`.
4. Push to the branch: `git push origin feature/name`.
5. Open a pull request.

Please ensure your code adheres to the existing style and includes relevant tests.

---

## 📜 License

FastCrypt is [MIT Licensed](LICENSE).

---

## 📚 References

- [RFC 8439 - ChaCha20 and Poly1305 for IETF Protocols](https://tools.ietf.org/html/rfc8439)

---
