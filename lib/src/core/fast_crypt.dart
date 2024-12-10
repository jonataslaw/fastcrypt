import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import '../algorithms/chacha20_poly1305.dart';
import '../models/encrypted_data.dart';
import '../streams/decryptor.dart';
import '../streams/encryptor.dart';
import 'constants.dart';

/// A cryptographic utility for high-performance encryption and decryption
/// using the ChaCha20-Poly1305 authenticated encryption algorithm.
class FastCrypt {
  /// Constructor for `FastCrypt`.
  const FastCrypt();

  // -------------------------- Synchronous Methods --------------------------

  /// Encrypts a plaintext string and returns an [EncryptedString] object.
  ///
  /// - [plaintext]: The plaintext string to encrypt.
  /// - [key]: A 32-byte key. If not provided, a random key is generated.
  /// - [nonce]: A 12-byte nonce. If not provided, a random nonce is generated.
  /// - [aad]: Optional additional authenticated data.
  /// - [isUtf8]: If true, encodes the string as UTF-8; otherwise, uses code units.
  ///
  /// Returns an [EncryptedString] containing the encrypted data.
  EncryptedString encryptText(
    String plaintext, {
    Uint8List? key,
    Uint8List? nonce,
    Uint8List? aad,
    bool isUtf8 = false,
  }) {
    final encryptedData = encryptString(
      plaintext,
      key: key,
      nonce: nonce,
      aad: aad,
      isUtf8: isUtf8,
    );
    return EncryptedString.fromEncryptedData(encryptedData, isUtf8: isUtf8);
  }

  /// Decrypts an [EncryptedString] and returns the original plaintext string.
  ///
  /// - [encryptedText]: The encrypted string to decrypt.
  ///
  /// Returns the decrypted plaintext string.
  String decryptText(EncryptedString encryptedText) {
    final data = encryptedText.toEncryptedData();
    final decryptedBytes = decryptBytes(
      ciphertext: data.ciphertext,
      tag: data.tag,
      key: data.key,
      nonce: data.nonce,
      aad: data.aad,
    );
    return _bytesToString(decryptedBytes, encryptedText.isUtf8);
  }

  /// Encrypts a plaintext string and returns an [EncryptedData] object.
  ///
  /// - [plaintext]: The plaintext string to encrypt.
  /// - [key]: A 32-byte key. If not provided, a random key is generated.
  /// - [nonce]: A 12-byte nonce. If not provided, a random nonce is generated.
  /// - [aad]: Optional additional authenticated data.
  /// - [isUtf8]: If true, encodes the string as UTF-8; otherwise, uses code units.
  ///
  /// Returns an [EncryptedData] object containing the encrypted data.
  EncryptedData encryptString(
    String plaintext, {
    Uint8List? key,
    Uint8List? nonce,
    Uint8List? aad,
    bool isUtf8 = false,
  }) {
    final bytes = _stringToBytes(plaintext, isUtf8);
    return encryptBytes(
      bytes,
      key: key,
      nonce: nonce,
      aad: aad,
    );
  }

  /// Decrypts ciphertext to retrieve the original plaintext string.
  ///
  /// - [ciphertext]: The encrypted bytes.
  /// - [tag]: The authentication tag.
  /// - [key]: The 32-byte key used for encryption.
  /// - [nonce]: The 12-byte nonce used during encryption.
  /// - [aad]: Optional additional authenticated data.
  /// - [isUtf8]: If true, decodes the string as UTF-8; otherwise, uses code units.
  ///
  /// Returns the decrypted plaintext string.
  ///
  /// Throws an exception if authentication fails.
  String decryptString({
    required List<int> ciphertext,
    required Uint8List tag,
    required Uint8List key,
    required Uint8List nonce,
    Uint8List? aad,
    bool isUtf8 = false,
  }) {
    final decryptedBytes = decryptBytes(
      ciphertext: ciphertext,
      tag: tag,
      key: key,
      nonce: nonce,
      aad: aad,
    );
    return _bytesToString(decryptedBytes, isUtf8);
  }

  /// Encrypts plaintext bytes and returns an [EncryptedData] object.
  ///
  /// - [plaintext]: The plaintext bytes to encrypt.
  /// - [key]: A 32-byte key. If not provided, a random key is generated.
  /// - [nonce]: A 12-byte nonce. If not provided, a random nonce is generated.
  /// - [aad]: Optional additional authenticated data.
  ///
  /// Returns an [EncryptedData] object containing ciphertext, tag, key, and nonce.
  EncryptedData encryptBytes(
    List<int> plaintext, {
    Uint8List? key,
    Uint8List? nonce,
    Uint8List? aad,
  }) {
    key ??= generateKey();
    nonce ??= generateNonce();
    aad ??= _aadNoop;

    final (ciphertext, tag) = encrypt(
      plaintext,
      key: key,
      nonce: nonce,
      aad: aad,
    );

    return EncryptedData(
      ciphertext: ciphertext,
      key: key,
      tag: tag,
      nonce: nonce,
      aad: aad,
    );
  }

  /// Decrypts ciphertext bytes and returns the original plaintext bytes.
  ///
  /// - [ciphertext]: The encrypted bytes.
  /// - [tag]: The authentication tag.
  /// - [key]: The 32-byte key used for encryption.
  /// - [nonce]: The 12-byte nonce used during encryption.
  /// - [aad]: Optional additional authenticated data.
  ///
  /// Returns the decrypted plaintext bytes.
  ///
  /// Throws an exception if authentication fails.
  List<int> decryptBytes({
    required List<int> ciphertext,
    required Uint8List tag,
    required Uint8List key,
    required Uint8List nonce,
    Uint8List? aad,
  }) {
    return decrypt(
      ciphertext,
      tag,
      key: key,
      nonce: nonce,
      aad: aad,
    );
  }

  // -------------------------- Asynchronous Methods --------------------------

  /// Asynchronously encrypts a plaintext string and returns an [EncryptedString].
  ///
  /// - [plaintext]: The plaintext string to encrypt.
  /// - [key]: A 32-byte key. If not provided, a random key is generated.
  /// - [nonce]: A 12-byte nonce. If not provided, a random nonce is generated.
  /// - [aad]: Optional additional authenticated data.
  /// - [isUtf8]: If true, encodes the string as UTF-8; otherwise, uses code units.
  ///
  /// Returns a [Future] containing an [EncryptedString] with the encrypted data.
  Future<EncryptedString> encryptTextAsync(
    String plaintext, {
    Uint8List? key,
    Uint8List? nonce,
    Uint8List? aad,
    bool isUtf8 = false,
  }) async {
    final encryptedData = await encryptStringAsync(
      plaintext,
      key: key,
      nonce: nonce,
      aad: aad,
      isUtf8: isUtf8,
    );
    return EncryptedString.fromEncryptedData(encryptedData, isUtf8: isUtf8);
  }

  /// Asynchronously decrypts an [EncryptedString] and returns the original plaintext string.
  ///
  /// - [encryptedText]: The encrypted string to decrypt.
  ///
  /// Returns a [Future] containing the decrypted plaintext string.
  Future<String> decryptTextAsync(EncryptedString encryptedText) async {
    final data = encryptedText.toEncryptedData();
    final decryptedBytes = await decryptBytesAsync(
      ciphertext: data.ciphertext,
      tag: data.tag,
      key: data.key,
      nonce: data.nonce,
      aad: data.aad,
    );
    return _bytesToString(decryptedBytes, encryptedText.isUtf8);
  }

  /// Asynchronously encrypts a plaintext string and returns an [EncryptedData] object.
  ///
  /// - [plaintext]: The plaintext string to encrypt.
  /// - [key]: A 32-byte key. If not provided, a random key is generated.
  /// - [nonce]: A 12-byte nonce. If not provided, a random nonce is generated.
  /// - [aad]: Optional additional authenticated data.
  /// - [isUtf8]: If true, encodes the string as UTF-8; otherwise, uses code units.
  ///
  /// Returns a [Future] containing an [EncryptedData] object with the encrypted data.
  Future<EncryptedData> encryptStringAsync(
    String plaintext, {
    Uint8List? key,
    Uint8List? nonce,
    Uint8List? aad,
    bool isUtf8 = false,
  }) async {
    final bytes = _stringToBytes(plaintext, isUtf8);
    return encryptBytesAsync(
      bytes,
      key: key,
      nonce: nonce,
      aad: aad,
    );
  }

  /// Asynchronously decrypts ciphertext and returns the original plaintext string.
  ///
  /// - [ciphertext]: The encrypted bytes.
  /// - [tag]: The authentication tag.
  /// - [key]: The 32-byte key used for encryption.
  /// - [nonce]: The 12-byte nonce used during encryption.
  /// - [aad]: Optional additional authenticated data.
  /// - [isUtf8]: If true, decodes the string as UTF-8; otherwise, uses code units.
  ///
  /// Returns a [Future] containing the decrypted plaintext string.
  ///
  /// Throws an exception if authentication fails.
  Future<String> decryptStringAsync({
    required List<int> ciphertext,
    required Uint8List tag,
    required Uint8List key,
    required Uint8List nonce,
    Uint8List? aad,
    bool isUtf8 = false,
  }) async {
    final decryptedBytes = await decryptBytesAsync(
      ciphertext: ciphertext,
      tag: tag,
      key: key,
      nonce: nonce,
      aad: aad,
    );
    return _bytesToString(decryptedBytes, isUtf8);
  }

  /// Asynchronously encrypts plaintext bytes and returns an [EncryptedData] object.
  ///
  /// - [plaintext]: The plaintext bytes to encrypt.
  /// - [key]: A 32-byte key. If not provided, a random key is generated.
  /// - [nonce]: A 12-byte nonce. If not provided, a random nonce is generated.
  /// - [aad]: Optional additional authenticated data.
  ///
  /// Returns a [Future] containing an [EncryptedData] object with the encrypted data.
  Future<EncryptedData> encryptBytesAsync(
    List<int> plaintext, {
    Uint8List? key,
    Uint8List? nonce,
    Uint8List? aad,
  }) async {
    key ??= generateKey();
    nonce ??= generateNonce();
    aad ??= _aadNoop;

    final encryptor = ChaCha20Poly1305Encryptor(
      key: key,
      nonce: nonce,
      aad: aad,
    );

    final builder = BytesBuilder(copy: false);

    await for (final chunk
        in Stream<List<int>>.fromIterable([plaintext]).transform(encryptor)) {
      builder.add(chunk);
    }

    final encryptedData = builder.toBytes();
    final tag = encryptedData
        .sublist(encryptedData.length - FastCryptContants.tagLength);
    final ciphertext = encryptedData.sublist(
        0, encryptedData.length - FastCryptContants.tagLength);

    return EncryptedData(
      ciphertext: ciphertext,
      key: key,
      tag: tag,
      nonce: nonce,
      aad: aad,
    );
  }

  /// Asynchronously decrypts ciphertext bytes and returns the original plaintext bytes.
  ///
  /// - [ciphertext]: The encrypted bytes.
  /// - [tag]: The authentication tag.
  /// - [key]: The 32-byte key used for encryption.
  /// - [nonce]: The 12-byte nonce used during encryption.
  /// - [aad]: Optional additional authenticated data.
  ///
  /// Returns a [Future] containing the decrypted plaintext bytes.
  ///
  /// Throws an exception if authentication fails.
  Future<Uint8List> decryptBytesAsync({
    required List<int> ciphertext,
    required Uint8List tag,
    required Uint8List key,
    required Uint8List nonce,
    Uint8List? aad,
  }) async {
    final data = [...ciphertext, ...tag];

    final decryptor = ChaCha20Poly1305Decryptor(
      key: key,
      nonce: nonce,
      aad: aad,
    );

    final builder = BytesBuilder(copy: false);

    await for (final chunk
        in Stream<List<int>>.fromIterable([data]).transform(decryptor)) {
      builder.add(chunk);
    }

    return builder.toBytes();
  }

  /// Encrypts plaintext using ChaCha20-Poly1305 AEAD cipher.
  ///
  /// - [plaintext]: The data to encrypt.
  /// - [key]: A 32-byte key for encryption.
  /// - [nonce]: A 12-byte nonce for encryption.
  /// - [aad]: Optional additional authenticated data.
  ///
  /// Returns an [EncryptionResult] containing the ciphertext and authentication tag.
  ///
  /// Throws an exception if the key or nonce lengths are invalid.
  EncryptionResult encrypt(
    List<int> plaintext, {
    required Uint8List key,
    required Uint8List nonce,
    Uint8List? aad,
  }) {
    return ChaCha20Poly1305(key: key, nonce: nonce, aad: aad ?? _aadNoop)
        .encrypt(plaintext);
  }

  /// Decrypts ciphertext using ChaCha20-Poly1305 AEAD cipher.
  ///
  /// - [ciphertext]: The encrypted data to decrypt.
  /// - [tag]: The 16-byte authentication tag.
  /// - [key]: The 32-byte key used for encryption.
  /// - [nonce]: The 12-byte nonce used during encryption.
  /// - [aad]: Optional additional authenticated data.
  ///
  /// Returns the decrypted plaintext as a [List<int>].
  ///
  /// Throws an exception if authentication fails or if the key or nonce lengths are invalid.
  List<int> decrypt(
    List<int> ciphertext,
    Uint8List tag, {
    required Uint8List key,
    required Uint8List nonce,
    Uint8List? aad,
  }) {
    return ChaCha20Poly1305(key: key, nonce: nonce, aad: aad ?? _aadNoop)
        .decrypt(ciphertext, tag);
  }

  // -------------------------- Static Utility Methods --------------------------

  /// Generates a secure random 32-byte key suitable for ChaCha20-Poly1305 encryption.
  ///
  /// Returns a [Uint8List] containing the generated key.
  static Uint8List generateKey() => _randomBytes(FastCryptContants.keyLength);

  /// Generates a secure random 12-byte nonce suitable for ChaCha20-Poly1305 encryption.
  ///
  /// Returns a [Uint8List] containing the generated nonce.
  static Uint8List generateNonce() =>
      _randomBytes(FastCryptContants.nonceLength);

  static Uint8List _randomBytes(int length) {
    final random = Random.secure();
    return Uint8List.fromList(
        List.generate(length, (_) => random.nextInt(256)));
  }

  // -------------------------- Private Helpers --------------------------
  /// Converts a string to bytes using the specified encoding.
  List<int> _stringToBytes(String input, bool isUtf8) {
    return isUtf8 ? utf8.encode(input) : input.codeUnits;
  }

  /// Converts bytes to a string using the specified encoding.
  String _bytesToString(List<int> bytes, bool isUtf8) {
    return isUtf8 ? utf8.decode(bytes) : String.fromCharCodes(bytes);
  }

  static final _aadNoop = Uint8List(0);
}
