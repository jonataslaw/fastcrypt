import 'dart:typed_data';

import '../core/constants.dart';
import '../core/utils.dart';
import '../exceptions/authentication_exception.dart';

/// Represents the result of an encryption operation.
typedef EncryptionResult = (List<int> ciphertext, Uint8List tag);

/// ChaCha20-Poly1305 cipher implementation.
class ChaCha20Poly1305 {
  final Uint8List key;
  final Uint8List nonce;
  final Uint8List aad;

  /// Initializes the cipher with the given [key], [nonce], and optional [aad].
  const ChaCha20Poly1305({
    required this.key,
    required this.nonce,
    required this.aad,
  });

  /// Encrypts the [plaintext] and returns the ciphertext and authentication tag.
  ///
  /// Returns an [EncryptionResult] containing the ciphertext and tag.
  EncryptionResult encrypt(List<int> plaintext) {
    final ciphertext = chacha20Encrypt(key, 1, nonce, plaintext);
    final polyKey = poly1305KeyGen(key, nonce);
    final tag = calculateTag(ciphertext, aad, polyKey);

    return (ciphertext, tag);
  }

  /// Decrypts the [ciphertext] using the provided [tag] and returns the plaintext.
  ///
  /// Throws [AuthenticationException] if the tag is invalid.
  List<int> decrypt(List<int> ciphertext, Uint8List tag) {
    if (tag.length != FastCryptContants.tagLength) {
      throw ArgumentError('Invalid tag length');
    }
    final polyKey = poly1305KeyGen(key, nonce);
    final expectedTag = calculateTag(ciphertext, aad, polyKey);

    if (!constantTimeCompare(tag, expectedTag)) {
      throw AuthenticationException('Invalid authentication tag');
    }

    // Decrypt ciphertext
    return chacha20Encrypt(key, 1, nonce, ciphertext);
  }
}