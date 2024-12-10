import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:fastcrypt/fastcrypt.dart';
import 'package:fastcrypt/src/algorithms/chacha20_poly1305.dart';
import 'package:fastcrypt/src/algorithms/poly1305_mac.dart';
import 'package:fastcrypt/src/core/constants.dart';
import 'package:fastcrypt/src/core/utils.dart';
import 'package:test/test.dart';

void main() {
  // final chacha = ChaCha20Poly1305();
  final fastCrypt = FastCrypt();

  // Original tests ensuring compliance with the RFC
  test('test Quarter round', () {
    final testState = Uint32List.fromList([
      0x11111111,
      0x01020304,
      0x9b8d6f43,
      0x01234567,
    ]);

    quarterRound(testState, 0, 1, 2, 3);

    expect(testState[0], 0xea2a92f4);
    expect(testState[1], 0xcb1cf8ce);
    expect(testState[2], 0x4581472e);
    expect(testState[3], 0x5881c4bb);
  });

  test('test ChaCha20 block function', () {
    // Key bytes as per RFC
    final keyBytes = [
      // 32 bytes of key data as per the RFC
      for (int i = 0; i < 32; i++) i,
    ].toUint8List();

    // Nonce bytes as per RFC
    final nonceBytes = [
      0x00,
      0x00,
      0x00,
      0x09,
      0x00,
      0x00,
      0x00,
      0x4a,
      0x00,
      0x00,
      0x00,
      0x00,
    ].toUint8List();

    // Counter
    int counter = 1;

    // Calculate block
    List<int> block = chacha20Block(keyBytes, counter, nonceBytes);

    // Expected output bytes (from RFC), adjusted to little-endian order
    List<int> expectedOutputBytes = [
      0x10, 0xf1, 0xe7, 0xe4, // word 0
      0xd1, 0x3b, 0x59, 0x15, // word 1
      0x50, 0x0f, 0xdd, 0x1f, // word 2
      0xa3, 0x20, 0x71, 0xc4, // word 3
      0xc7, 0xd1, 0xf4, 0xc7, // word 4
      0x33, 0xc0, 0x68, 0x03, // word 5
      0x04, 0x22, 0xaa, 0x9a, // word 6
      0xc3, 0xd4, 0x6c, 0x4e, // word 7
      0xd2, 0x82, 0x64, 0x46, // word 8
      0x07, 0x9f, 0xaa, 0x09, // word 9
      0x14, 0xc2, 0xd7, 0x05, // word10
      0xd9, 0x8b, 0x02, 0xa2, // word11
      0xb5, 0x12, 0x9c, 0xd1, // word12
      0xde, 0x16, 0x4e, 0xb9, // word13
      0xcb, 0xd0, 0x83, 0xe8, // word14
      0xa2, 0x50, 0x3c, 0x4e, // word15
    ];

    // Compare the generated block with the expected output
    expect(block, expectedOutputBytes);
  });

  test('test ChaCha20 encryption', () {
    // Key bytes as per RFC
    final keyBytes = [
      0x00,
      0x01,
      0x02,
      0x03,
      0x04,
      0x05,
      0x06,
      0x07,
      0x08,
      0x09,
      0x0a,
      0x0b,
      0x0c,
      0x0d,
      0x0e,
      0x0f,
      0x10,
      0x11,
      0x12,
      0x13,
      0x14,
      0x15,
      0x16,
      0x17,
      0x18,
      0x19,
      0x1a,
      0x1b,
      0x1c,
      0x1d,
      0x1e,
      0x1f,
    ].toUint8List();

    // Nonce bytes as per RFC
    final nonceBytes = [
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x4a,
      0x00,
      0x00,
      0x00,
      0x00
    ].toUint8List();

    // Plaintext as per RFC
    final plaintext = [
      0x4c,
      0x61,
      0x64,
      0x69,
      0x65,
      0x73,
      0x20,
      0x61,
      0x6e,
      0x64,
      0x20,
      0x47,
      0x65,
      0x6e,
      0x74,
      0x6c,
      0x65,
      0x6d,
      0x65,
      0x6e,
      0x20,
      0x6f,
      0x66,
      0x20,
      0x74,
      0x68,
      0x65,
      0x20,
      0x63,
      0x6c,
      0x61,
      0x73,
      0x73,
      0x20,
      0x6f,
      0x66,
      0x20,
      0x27,
      0x39,
      0x39,
      0x3a,
      0x20,
      0x49,
      0x66,
      0x20,
      0x49,
      0x20,
      0x63,
      0x6f,
      0x75,
      0x6c,
      0x64,
      0x20,
      0x6f,
      0x66,
      0x66,
      0x65,
      0x72,
      0x20,
      0x79,
      0x6f,
      0x75,
      0x20,
      0x6f,
      0x6e,
      0x6c,
      0x79,
      0x20,
      0x6f,
      0x6e,
      0x65,
      0x20,
      0x74,
      0x69,
      0x70,
      0x20,
      0x66,
      0x6f,
      0x72,
      0x20,
      0x74,
      0x68,
      0x65,
      0x20,
      0x66,
      0x75,
      0x74,
      0x75,
      0x72,
      0x65,
      0x2c,
      0x20,
      0x73,
      0x75,
      0x6e,
      0x73,
      0x63,
      0x72,
      0x65,
      0x65,
      0x6e,
      0x20,
      0x77,
      0x6f,
      0x75,
      0x6c,
      0x64,
      0x20,
      0x62,
      0x65,
      0x20,
      0x69,
      0x74,
      0x2e
    ].toUint8List();

    // Perform encryption
    List<int> ciphertext = chacha20Encrypt(keyBytes, 1, nonceBytes, plaintext);

    // Expected ciphertext as per RFC
    List<int> expectedCiphertext = [
      0x6e,
      0x2e,
      0x35,
      0x9a,
      0x25,
      0x68,
      0xf9,
      0x80,
      0x41,
      0xba,
      0x07,
      0x28,
      0xdd,
      0x0d,
      0x69,
      0x81,
      0xe9,
      0x7e,
      0x7a,
      0xec,
      0x1d,
      0x43,
      0x60,
      0xc2,
      0x0a,
      0x27,
      0xaf,
      0xcc,
      0xfd,
      0x9f,
      0xae,
      0x0b,
      0xf9,
      0x1b,
      0x65,
      0xc5,
      0x52,
      0x47,
      0x33,
      0xab,
      0x8f,
      0x59,
      0x3d,
      0xab,
      0xcd,
      0x62,
      0xb3,
      0x57,
      0x16,
      0x39,
      0xd6,
      0x24,
      0xe6,
      0x51,
      0x52,
      0xab,
      0x8f,
      0x53,
      0x0c,
      0x35,
      0x9f,
      0x08,
      0x61,
      0xd8,
      0x07,
      0xca,
      0x0d,
      0xbf,
      0x50,
      0x0d,
      0x6a,
      0x61,
      0x56,
      0xa3,
      0x8e,
      0x08,
      0x8a,
      0x22,
      0xb6,
      0x5e,
      0x52,
      0xbc,
      0x51,
      0x4d,
      0x16,
      0xcc,
      0xf8,
      0x06,
      0x81,
      0x8c,
      0xe9,
      0x1a,
      0xb7,
      0x79,
      0x37,
      0x36,
      0x5a,
      0xf9,
      0x0b,
      0xbf,
      0x74,
      0xa3,
      0x5b,
      0xe6,
      0xb4,
      0x0b,
      0x8e,
      0xed,
      0xf2,
      0x78,
      0x5e,
      0x42,
      0x87,
      0x4d,
    ];

    // Verify ciphertext
    expect(ciphertext.length, expectedCiphertext.length);
    expect(ciphertext, expectedCiphertext);
  });

  test('test Poly1305', () {
    final key = [
      0x85,
      0xd6,
      0xbe,
      0x78,
      0x57,
      0x55,
      0x6d,
      0x33,
      0x7f,
      0x44,
      0x52,
      0xfe,
      0x42,
      0xd5,
      0x06,
      0xa8,
      0x01,
      0x03,
      0x80,
      0x8a,
      0xfb,
      0x0d,
      0xb2,
      0xfd,
      0x4a,
      0xbf,
      0xf6,
      0xaf,
      0x41,
      0x49,
      0xf5,
      0x1b,
    ].toUint8List();

    // Message
    String msgStr = 'Cryptographic Forum Research Group';
    Uint8List msg = msgStr.codeUnits.toUint8List();

    // Create Poly1305 MAC
    final mac = Poly1305Mac(key);

    // Update with message
    mac.update(msg);

    // Get tag
    final tag = mac.finish();

    // Expected tag
    List<int> expectedTag = [
      0xa8,
      0x06,
      0x1d,
      0xc1,
      0x30,
      0x51,
      0x36,
      0xc6,
      0xc2,
      0x2b,
      0x8b,
      0xaf,
      0x0c,
      0x01,
      0x27,
      0xa9,
    ].toUint8List();
    expect(tag.length, expectedTag.length);
    expect(tag, expectedTag);
  });

  test('test Poly1305 key generation', () {
    final key = [
      0x80,
      0x81,
      0x82,
      0x83,
      0x84,
      0x85,
      0x86,
      0x87,
      0x88,
      0x89,
      0x8a,
      0x8b,
      0x8c,
      0x8d,
      0x8e,
      0x8f,
      0x90,
      0x91,
      0x92,
      0x93,
      0x94,
      0x95,
      0x96,
      0x97,
      0x98,
      0x99,
      0x9a,
      0x9b,
      0x9c,
      0x9d,
      0x9e,
      0x9f,
    ].toUint8List();

    // Nonce
    final nonce = [
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x01,
      0x02,
      0x03,
      0x04,
      0x05,
      0x06,
      0x07,
    ].toUint8List();

    // Generate Poly1305 key
    final polyKey = poly1305KeyGen(key, nonce);

    // Expected key
    List<int> expectedPolyKey = [
      0x8a,
      0xd5,
      0xa0,
      0x8b,
      0x90,
      0x5f,
      0x81,
      0xcc,
      0x81,
      0x50,
      0x40,
      0x27,
      0x4a,
      0xb2,
      0x94,
      0x71,
      0xa8,
      0x33,
      0xb6,
      0x37,
      0xe3,
      0xfd,
      0x0d,
      0xa5,
      0x08,
      0xdb,
      0xb8,
      0xe2,
      0xfd,
      0xd1,
      0xa6,
      0x46,
    ];

    expect(polyKey.length, expectedPolyKey.length);
    expect(polyKey, expectedPolyKey);
  });

  test('test AEAD ChaCha20-Poly1305 encryption', () {
    final key = [
      0x80,
      0x81,
      0x82,
      0x83,
      0x84,
      0x85,
      0x86,
      0x87,
      0x88,
      0x89,
      0x8a,
      0x8b,
      0x8c,
      0x8d,
      0x8e,
      0x8f,
      0x90,
      0x91,
      0x92,
      0x93,
      0x94,
      0x95,
      0x96,
      0x97,
      0x98,
      0x99,
      0x9a,
      0x9b,
      0x9c,
      0x9d,
      0x9e,
      0x9f,
    ].toUint8List();

    // Nonce
    final nonce = [
      0x07,
      0x00,
      0x00,
      0x00,
      0x40,
      0x41,
      0x42,
      0x43,
      0x44,
      0x45,
      0x46,
      0x47,
    ].toUint8List();

    // AAD
    final aad = [
      0x50,
      0x51,
      0x52,
      0x53,
      0xc0,
      0xc1,
      0xc2,
      0xc3,
      0xc4,
      0xc5,
      0xc6,
      0xc7,
    ].toUint8List();

    // Plaintext
    String plaintextStr =
        "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    final plaintext = utf8.encode(plaintextStr);

    final chacha = ChaCha20Poly1305(key: key, nonce: nonce, aad: aad);

    // Perform encryption
    final (ciphertext, tag) = chacha.encrypt(plaintext);

    // Expected ciphertext and tag (from RFC)
    final expectedCiphertext = [
      0xd3,
      0x1a,
      0x8d,
      0x34,
      0x64,
      0x8e,
      0x60,
      0xdb,
      0x7b,
      0x86,
      0xaf,
      0xbc,
      0x53,
      0xef,
      0x7e,
      0xc2,
      0xa4,
      0xad,
      0xed,
      0x51,
      0x29,
      0x6e,
      0x08,
      0xfe,
      0xa9,
      0xe2,
      0xb5,
      0xa7,
      0x36,
      0xee,
      0x62,
      0xd6,
      0x3d,
      0xbe,
      0xa4,
      0x5e,
      0x8c,
      0xa9,
      0x67,
      0x12,
      0x82,
      0xfa,
      0xfb,
      0x69,
      0xda,
      0x92,
      0x72,
      0x8b,
      0x1a,
      0x71,
      0xde,
      0x0a,
      0x9e,
      0x06,
      0x0b,
      0x29,
      0x05,
      0xd6,
      0xa5,
      0xb6,
      0x7e,
      0xcd,
      0x3b,
      0x36,
      0x92,
      0xdd,
      0xbd,
      0x7f,
      0x2d,
      0x77,
      0x8b,
      0x8c,
      0x98,
      0x03,
      0xae,
      0xe3,
      0x28,
      0x09,
      0x1b,
      0x58,
      0xfa,
      0xb3,
      0x24,
      0xe4,
      0xfa,
      0xd6,
      0x75,
      0x94,
      0x55,
      0x85,
      0x80,
      0x8b,
      0x48,
      0x31,
      0xd7,
      0xbc,
      0x3f,
      0xf4,
      0xde,
      0xf0,
      0x8e,
      0x4b,
      0x7a,
      0x9d,
      0xe5,
      0x76,
      0xd2,
      0x65,
      0x86,
      0xce,
      0xc6,
      0x4b,
      0x61,
      0x16,
    ].toUint8List();

    final expectedTag = [
      0x1a,
      0xe1,
      0x0b,
      0x59,
      0x4f,
      0x09,
      0xe2,
      0x6a,
      0x7e,
      0x90,
      0x2e,
      0xcb,
      0xd0,
      0x60,
      0x06,
      0x91,
    ].toUint8List();

    // Verify ciphertext
    expect(ciphertext.length, expectedCiphertext.length);
    expect(ciphertext, expectedCiphertext);

    // Verify tag
    expect(tag.length, expectedTag.length);
    expect(tag, expectedTag);
  });

  // Additional tests

  test('ChaCha20-Poly1305 encryption and decryption', () {
    final key =
        List<int>.generate(FastCryptContants.keyLength, (i) => i).toUint8List();
    final nonce =
        List<int>.generate(FastCryptContants.nonceLength, (i) => i + 0x20)
            .toUint8List();

    final plaintext = utf8.encode(
        'Hello, world! This is a test of ChaCha20-Poly1305 encryption.');

    final aad = utf8.encode('Some additional data');

    // Encryption
    final chacha = ChaCha20Poly1305(key: key, nonce: nonce, aad: aad);

    // Perform encryption
    final (ciphertext, tag) = chacha.encrypt(plaintext);

    // Decryption
    List<int> decryptedPlaintext = chacha.decrypt(ciphertext, tag);

    // Verify that decrypted plaintext matches original plaintext
    expect(decryptedPlaintext, plaintext);
  });

  test('ChaCha20-Poly1305 decryption with wrong tag fails', () {
    final key =
        List<int>.generate(FastCryptContants.keyLength, (i) => i).toUint8List();
    final nonce =
        List<int>.generate(FastCryptContants.nonceLength, (i) => i + 0x20)
            .toUint8List();

    final plaintext = utf8.encode(
        'Hello, world! This is a test of ChaCha20-Poly1305 encryption.');

    final aad = utf8.encode('Some additional data');

    final chacha = ChaCha20Poly1305(key: key, nonce: nonce, aad: aad);

    // Encryption
    final (ciphertext, tag) = chacha.encrypt(plaintext);

    // Modify the tag to simulate an authentication failure
    tag[0] ^= 0xff; // Invalidate the tag

    // Decryption should throw AuthenticationException
    expect(
        () => chacha.decrypt(
            ciphertext, tag), // Decryption should throw AuthenticationException
        throwsA(isA<AuthenticationException>()));
  });

  test('ChaCha20-Poly1305 with zero-length plaintext and zero-length AAD', () {
    final key =
        List<int>.generate(FastCryptContants.keyLength, (i) => i).toUint8List();
    final nonce =
        List<int>.generate(FastCryptContants.nonceLength, (i) => i + 0x20)
            .toUint8List();

    final plaintext = Uint8List(0); // Zero-length plaintext

    final aad = Uint8List(0); // Zero-length AAD

    final chacha = ChaCha20Poly1305(key: key, nonce: nonce, aad: aad);

    // Encryption
    final (ciphertext, tag) = chacha.encrypt(plaintext);

    // Decryption
    final decryptedPlaintext = chacha.decrypt(ciphertext, tag);

    // Verify that decrypted plaintext matches original plaintext
    expect(decryptedPlaintext, plaintext);
  });

  test('ChaCha20-Poly1305 with incorrect key length throws error', () {
    final key = List<int>.generate(16, (i) => i)
        .toUint8List(); // 16 bytes instead of 32
    final nonce =
        List<int>.generate(FastCryptContants.nonceLength, (i) => i + 0x20)
            .toUint8List();

    final plaintext = utf8.encode('Test plaintext');
    final aad = utf8.encode('Test AAD');

    final chacha = ChaCha20Poly1305(key: key, nonce: nonce, aad: aad);

    // Encryption should throw ArgumentError
    expect(() => chacha.encrypt(plaintext), throwsArgumentError);
  });

  test('ChaCha20-Poly1305 with large plaintext', () {
    final key =
        List<int>.generate(FastCryptContants.keyLength, (i) => i).toUint8List();
    final nonce =
        List<int>.generate(FastCryptContants.nonceLength, (i) => i + 0x20)
            .toUint8List();

    // Generate a large plaintext (e.g., 1 MB)
    final plaintext =
        List<int>.filled(1024 * 1024, 0x61).toUint8List(); // 'a' * 1MB

    final aad = utf8.encode('Some additional data');

    final chacha = ChaCha20Poly1305(key: key, nonce: nonce, aad: aad);

    // Encryption
    final (ciphertext, tag) = chacha.encrypt(plaintext);

    // Decryption
    List<int> decryptedPlaintext = chacha.decrypt(ciphertext, tag);

    // Verify that decrypted plaintext matches original plaintext
    expect(decryptedPlaintext, plaintext);
  });

  group('ChaCha20Poly1305 Additional Tests', () {
    test('test encrypt/decrypt string convenience methods', () {
      final key = FastCrypt.generateKey();
      final nonce = FastCrypt.generateNonce();
      final plaintext = 'Hello, World!';
      final aad = utf8.encode('Additional data');

      final encrypted = fastCrypt.encryptString(
        plaintext,
        key: key,
        nonce: nonce,
        aad: aad,
      );

      final decrypted = fastCrypt.decryptString(
        ciphertext: encrypted.ciphertext,
        tag: encrypted.tag,
        key: encrypted.key,
        nonce: encrypted.nonce,
        aad: aad,
      );

      expect(decrypted, plaintext);
    });

    test('test encryption with generated key and nonce', () {
      final plaintext = utf8.encode('Test message');
      final encrypted = fastCrypt.encryptBytes(plaintext);

      expect(encrypted.key.length, FastCryptContants.keyLength);
      expect(encrypted.nonce.length, FastCryptContants.nonceLength);
      expect(encrypted.tag.length, FastCryptContants.tagLength);
    });

    test('test invalid nonce length', () {
      final key = FastCrypt.generateKey();
      final invalidNonce =
          List<int>.generate(8, (i) => i).toUint8List(); // Wrong length
      final plaintext = utf8.encode('Test');

      expect(
        () => fastCrypt.encryptBytes(plaintext, key: key, nonce: invalidNonce),
        throwsArgumentError,
      );
    });

    test('test invalid tag length during decryption', () {
      final key = FastCrypt.generateKey();
      final nonce = FastCrypt.generateNonce();
      final invalidTag =
          List<int>.generate(8, (i) => i).toUint8List(); // Wrong length
      final ciphertext = List<int>.generate(16, (i) => i).toUint8List();

      expect(
        () => fastCrypt.decryptBytes(
          ciphertext: ciphertext,
          tag: invalidTag,
          key: key,
          nonce: nonce,
        ),
        throwsArgumentError,
      );
    });

    test('test decryption with modified ciphertext fails', () {
      final plaintext = utf8.encode('Original message');
      final encrypted = fastCrypt.encryptBytes(plaintext);

      // Modify the ciphertext
      encrypted.ciphertext[0] ^= 1;

      expect(
        () => fastCrypt.decryptBytes(
          ciphertext: encrypted.ciphertext,
          tag: encrypted.tag,
          key: encrypted.key,
          nonce: encrypted.nonce,
        ),
        throwsA(isA<AuthenticationException>()),
      );
    });

    test('test encryption with different AAD produces different tags', () {
      final key = FastCrypt.generateKey();
      final nonce = FastCrypt.generateNonce();
      final plaintext = utf8.encode('Test message');
      final aad1 = utf8.encode('AAD 1');
      final aad2 = utf8.encode('AAD 2');

      final result1 = ChaCha20Poly1305(
        key: key,
        nonce: nonce,
        aad: aad1,
      ).encrypt(plaintext);

      final result2 = ChaCha20Poly1305(
        key: key,
        nonce: nonce,
        aad: aad2,
      ).encrypt(plaintext);

      expect(result1.$2, isNot(equals(result2.$2)));
    });

    test('test decryption with wrong AAD fails', () {
      final plaintext = utf8.encode('Test message');
      final aad1 = utf8.encode('AAD 1');
      final aad2 = utf8.encode('AAD 2');

      final encrypted = fastCrypt.encryptBytes(plaintext, aad: aad1);

      expect(
        () => fastCrypt.decryptBytes(
          ciphertext: encrypted.ciphertext,
          tag: encrypted.tag,
          key: encrypted.key,
          nonce: encrypted.nonce,
          aad: aad2,
        ),
        throwsA(isA<AuthenticationException>()),
      );
    });

    test(
        'test multiple encryptions with same key/nonce do not produce different results',
        () {
      final key = FastCrypt.generateKey();
      final nonce = FastCrypt.generateNonce();
      final plaintext = utf8.encode('Test message');
      final aad = utf8.encode('AAD');

      final result1 = ChaCha20Poly1305(
        key: key,
        nonce: nonce,
        aad: aad,
      ).encrypt(plaintext);

      final result2 = ChaCha20Poly1305(
        key: key,
        nonce: nonce,
        aad: aad,
      ).encrypt(plaintext);

      expect(result1.$1, equals(result2.$1));
      expect(result1.$2, equals(result2.$2));
    });

    test('test AuthenticationException message', () {
      final exception = AuthenticationException('Custom message');
      expect(exception.toString(), 'AuthenticationException: Custom message');
    });

    test('test EncryptedData constructor and properties', () {
      final ciphertext = List<int>.generate(16, (i) => i);
      final key = FastCrypt.generateKey();
      final tag = List<int>.generate(16, (i) => i).toUint8List();
      final nonce = FastCrypt.generateNonce();
      final aad = utf8.encode('AAD');

      final encryptedData = EncryptedData(
        ciphertext: ciphertext,
        key: key,
        tag: tag,
        nonce: nonce,
        aad: aad,
      );

      expect(encryptedData.ciphertext, equals(ciphertext));
      expect(encryptedData.key, equals(key));
      expect(encryptedData.tag, equals(tag));
      expect(encryptedData.nonce, equals(nonce));
      expect(encryptedData.aad, equals(aad));
      expect(encryptedData.toString(),
          'EncryptedData(ciphertext: $ciphertext, key: $key, tag: $tag, nonce: $nonce, aad: $aad)');
    });

    test('test EncryptedString constructor and properties', () {
      final ciphertext = List<int>.generate(16, (i) => i);
      final key = FastCrypt.generateKey();
      final tag = List<int>.generate(16, (i) => i).toUint8List();
      final nonce = FastCrypt.generateNonce();
      final aad = utf8.encode('AAD');

      final encryptedString = EncryptedString(
        ciphertext: ciphertext,
        key: key,
        tag: tag,
        nonce: nonce,
        aad: aad,
      );

      expect(encryptedString.ciphertext, equals(ciphertext));
      expect(encryptedString.key, equals(key));
      expect(encryptedString.tag, equals(tag));
      expect(encryptedString.nonce, equals(nonce));
      expect(encryptedString.aad, equals(aad));
      expect(encryptedString.toString(),
          'EncryptedString(ciphertext: $ciphertext, key: $key, tag: $tag, nonce: $nonce, aad: $aad, isUtf8: false)');
    });

    test('valid conversion to EncryptedData', () {
      final original = EncryptedString(
        ciphertext: List<int>.generate(16, (i) => i),
        key: FastCrypt.generateKey(),
        tag: List<int>.generate(16, (i) => i).toUint8List(),
        nonce: FastCrypt.generateNonce(),
        aad: utf8.encode('AAD'),
      );

      final converted = original.toEncryptedData();
      expect(converted.ciphertext, equals(original.ciphertext));
      expect(converted.key, equals(original.key));
      expect(converted.tag, equals(original.tag));
      expect(converted.nonce, equals(original.nonce));
      expect(converted.aad, equals(original.aad));
    });

    test('invalid encryption data length throws FormatException', () {
      // Mock an EncryptedString with invalid data length
      final encryptedString = EncryptedString(
        ciphertext: List<int>.generate(16, (i) => i),
        key: Uint8List(1), // Invalid lengths to trigger the exception
        tag: Uint8List(1),
        nonce: Uint8List(1),
        aad: utf8.encode('AAD'),
      );

      expect(
        () => encryptedString.toEncryptedData(),
        throwsA(isA<FormatException>().having(
          (error) => error.message,
          'message',
          'Invalid encryption data length',
        )),
      );
    });

    test('valid EncryptedData conversion', () {
      final data = EncryptedData(
        ciphertext: List<int>.generate(16, (i) => i),
        key: FastCrypt.generateKey(),
        tag: List<int>.generate(16, (i) => i).toUint8List(),
        nonce: FastCrypt.generateNonce(),
        aad: utf8.encode('AAD'),
      );

      final encryptedString = EncryptedString.fromEncryptedData(data);
      expect(encryptedString.ciphertext, equals(data.ciphertext));
      expect(encryptedString.key, equals(data.key));
      expect(encryptedString.tag, equals(data.tag));
      expect(encryptedString.nonce, equals(data.nonce));
      expect(encryptedString.aad, equals(data.aad));
      expect(encryptedString.isUtf8, equals(false));
    });

    test('invalid key length throws ArgumentError', () {
      final data = EncryptedData(
        ciphertext: List<int>.generate(16, (i) => i),
        key: Uint8List(15), // Invalid key length
        tag: List<int>.generate(16, (i) => i).toUint8List(),
        nonce: FastCrypt.generateNonce(),
        aad: utf8.encode('AAD'),
      );

      expect(
        () => EncryptedString.fromEncryptedData(data),
        throwsA(isA<ArgumentError>().having(
          (error) => error.message,
          'message',
          'Invalid key length',
        )),
      );
    });

    test('invalid nonce length throws ArgumentError', () {
      final data = EncryptedData(
        ciphertext: List<int>.generate(16, (i) => i),
        key: FastCrypt.generateKey(),
        tag: List<int>.generate(16, (i) => i).toUint8List(),
        nonce: Uint8List(11), // Invalid nonce length
        aad: utf8.encode('AAD'),
      );

      expect(
        () => EncryptedString.fromEncryptedData(data),
        throwsA(isA<ArgumentError>().having(
          (error) => error.message,
          'message',
          'Invalid nonce length',
        )),
      );
    });

    test('invalid tag length throws ArgumentError', () {
      final data = EncryptedData(
        ciphertext: List<int>.generate(16, (i) => i),
        key: FastCrypt.generateKey(),
        tag: Uint8List(15), // Invalid tag length
        nonce: FastCrypt.generateNonce(),
        aad: utf8.encode('AAD'),
      );

      expect(
        () => EncryptedString.fromEncryptedData(data),
        throwsA(isA<ArgumentError>().having(
          (error) => error.message,
          'message',
          'Invalid tag length',
        )),
      );
    });

    test('test EncryptedBytes constructor and properties', () {
      final ciphertext = List<int>.generate(16, (i) => i);
      final key = FastCrypt.generateKey();
      final tag = List<int>.generate(16, (i) => i).toUint8List();
      final nonce = FastCrypt.generateNonce();
      final aad = utf8.encode('AAD');

      final encryptedString = EncryptedBytes(
        ciphertext: ciphertext,
        key: key,
        tag: tag,
        nonce: nonce,
        aad: aad,
      );

      expect(encryptedString.ciphertext, equals(ciphertext));
      expect(encryptedString.key, equals(key));
      expect(encryptedString.tag, equals(tag));
      expect(encryptedString.nonce, equals(nonce));
      expect(encryptedString.aad, equals(aad));
      expect(encryptedString.toString(),
          'EncryptedBytes(ciphertext: $ciphertext, key: $key, tag: $tag, nonce: $nonce, aad: $aad)');
    });
  });

  group('Poly1305Mac Tests', () {
    test('initialization with key', () {
      final key = List<int>.filled(32, 1).toUint8List();
      final mac = Poly1305Mac(key);
      expect(mac, isNotNull);
    });

    test('update with single block', () {
      final key = List<int>.filled(32, 1).toUint8List();
      final mac = Poly1305Mac(key);
      final block = List<int>.filled(16, 2).toUint8List();
      mac.update(block);
      final result = mac.finish();
      expect(result.length, equals(16));
    });

    test('throw exception if update or finish after finish', () {
      final key = List<int>.filled(32, 1).toUint8List();
      final mac = Poly1305Mac(key);
      final block = List<int>.filled(16, 2).toUint8List();
      mac.update(block);
      final result = mac.finish();
      expect(result.length, equals(16));
      expect(() => mac.update(block), throwsStateError);
      expect(() => mac.finish(), throwsStateError);
    });

    test('update with multiple blocks', () {
      final key = List<int>.filled(32, 1).toUint8List();
      final mac = Poly1305Mac(key);
      final block = List<int>.filled(32, 2).toUint8List();
      mac.update(block);
      final result = mac.finish();
      expect(result.length, equals(16));
    });

    test('update with partial block', () {
      final key = List<int>.filled(32, 1).toUint8List();
      final mac = Poly1305Mac(key);
      final block = List<int>.filled(10, 2).toUint8List();
      mac.update(block);
      final result = mac.finish();
      expect(result.length, equals(16));
    });
  });

  group('ChaCha20Poly1305Encryptor Tests', () {
    late Uint8List key;
    late Uint8List nonce;

    setUp(() {
      key = Uint8List.fromList(List<int>.filled(32, 1));
      nonce = Uint8List.fromList(List<int>.filled(12, 2));
    });

    test('encryption with empty stream', () async {
      final encryptor = ChaCha20Poly1305Encryptor(
        key: key,
        nonce: nonce,
      );

      final inputStream = Stream<List<int>>.empty();
      final outputStream = inputStream.transform(encryptor);

      // Collect the output
      final result = await outputStream.toList();

      // Since there's no input data, the output should only contain the tag
      expect(result.length, equals(1)); // Only the tag
      expect(result[0].length, equals(16)); // Tag length

      // Decrypt
      final decryptor = ChaCha20Poly1305Decryptor(
        key: key,
        nonce: nonce,
      );

      final encryptedData = result[0]; // Contains only the tag

      final decryptedStream =
          Stream.fromIterable([encryptedData]).transform(decryptor);
      final decryptedResult = await decryptedStream.toList();

      // The decrypted data should be empty
      final decryptedData = decryptedResult.expand((e) => e).toList();
      expect(decryptedData.length, equals(0));
    });

    test('encryption with single chunk', () async {
      final encryptor = ChaCha20Poly1305Encryptor(
        key: key,
        nonce: nonce,
      );

      final inputData = List<int>.filled(64, 3);
      final inputStream = Stream.fromIterable([inputData]);
      final outputStream = inputStream.transform(encryptor);

      // Collect the output
      final result = await outputStream.toList();

      // The output should contain the encrypted data and the tag
      expect(result.length, equals(2));
      expect(result[0].length, equals(64)); // Encrypted data length
      expect(result[1].length, equals(16)); // Tag length

      // Combine encrypted data and tag for decryption
      final encryptedData = [...result[0], ...result[1]];

      // Decrypt
      final decryptor = ChaCha20Poly1305Decryptor(
        key: key,
        nonce: nonce,
      );

      final decryptedStream =
          Stream.fromIterable([encryptedData]).transform(decryptor);
      final decryptedResult = await decryptedStream.toList();

      // The decrypted data should match the original input
      final decryptedData = decryptedResult.expand((e) => e).toList();
      expect(decryptedData, equals(inputData));
    });

    test('encryption with AAD', () async {
      final aad = List<int>.filled(32, 4).toUint8List();
      final encryptor = ChaCha20Poly1305Encryptor(
        key: key,
        nonce: nonce,
        aad: aad,
      );

      final inputData = List<int>.filled(64, 3);
      final inputStream = Stream.fromIterable([inputData]);
      final outputStream = inputStream.transform(encryptor);

      // Collect the output
      final result = await outputStream.toList();

      // The output should contain the encrypted data and the tag
      expect(result.length, equals(2));
      expect(result[0].length, equals(64)); // Encrypted data length
      expect(result[1].length, equals(16)); // Tag length

      // Combine encrypted data and tag for decryption
      final encryptedData = [...result[0], ...result[1]];

      // Decrypt
      final decryptor = ChaCha20Poly1305Decryptor(
        key: key,
        nonce: nonce,
        aad: aad,
      );

      final decryptedStream =
          Stream.fromIterable([encryptedData]).transform(decryptor);
      final decryptedResult = await decryptedStream.toList();

      // The decrypted data should match the original input
      final decryptedData = decryptedResult.expand((e) => e).toList();
      expect(decryptedData, equals(inputData));
    });

    test('decryption fails with tampered data', () async {
      final encryptor = ChaCha20Poly1305Encryptor(
        key: key,
        nonce: nonce,
      );

      final inputData = List<int>.filled(64, 3);
      final inputStream = Stream.fromIterable([inputData]);
      final outputStream = inputStream.transform(encryptor);

      final result = await outputStream.toList();

      // Combine encrypted data and tag
      final encryptedData = [...result[0], ...result[1]];

      // Tamper with the encrypted data
      encryptedData[0] ^= 0x01; // Flip a bit

      // Decrypt and expect an exception
      final decryptor = ChaCha20Poly1305Decryptor(
        key: key,
        nonce: nonce,
      );

      final decryptedStream =
          Stream.fromIterable([encryptedData]).transform(decryptor);

      await expectLater(
        decryptedStream.toList(),
        throwsA(isA<AuthenticationException>()),
      );
    });
  });

  group('ChaCha20Poly1305Decryptor Tests', () {
    late Uint8List key;
    late Uint8List nonce;

    setUp(() {
      key = Uint8List.fromList(List<int>.filled(32, 1));
      nonce = Uint8List.fromList(List<int>.filled(12, 2));
    });

    test('decryption with empty stream', () async {
      final decryptor = ChaCha20Poly1305Decryptor(key: key, nonce: nonce);

      final inputStream = Stream<List<int>>.empty();

      expect(
        () => inputStream.transform(decryptor).toList(),
        throwsArgumentError,
      );
    });

    test('decryption with invalid tag', () async {
      final decryptor = ChaCha20Poly1305Decryptor(
        key: key,
        nonce: nonce,
      );

      final invalidData = [
        ...nonce,
        ...List<int>.filled(64, 3),
        ...List<int>.filled(16, 0)
      ];
      final inputStream = Stream.fromIterable([invalidData]);

      expect(
        () => inputStream.transform(decryptor).toList(),
        throwsA(isA<AuthenticationException>()),
      );
    });

    test('full encryption-decryption cycle', () async {
      final plaintext = List<int>.filled(128, 5);

      // Encrypt
      final encryptor = ChaCha20Poly1305Encryptor(
        key: key,
        nonce: nonce,
      );

      final encryptedData = (await Stream.fromIterable([plaintext])
          .transform(encryptor)
          .expand((chunk) => chunk)
          .toList());

      // Decrypt
      final decryptor = ChaCha20Poly1305Decryptor(
        key: key,
        nonce: nonce,
      );

      final decryptedData = (await Stream.fromIterable([encryptedData])
              .transform(decryptor)
              .expand((chunk) => chunk)
              .toList())
          .toUint8List();

      expect(decryptedData, equals(plaintext));
    });

    test('decryption with insufficient data', () async {
      final decryptor = ChaCha20Poly1305Decryptor(
        key: key,
        nonce: nonce,
      );

      // Create data shorter than nonce + tag length
      final insufficientData = List<int>.filled(20, 1); // Less than 28 bytes
      final inputStream = Stream.fromIterable([insufficientData]);

      expect(
        () => inputStream.transform(decryptor).toList(),
        throwsA(isA<AuthenticationException>()),
      );
    });

    test('full encryption-decryption cycle with AAD', () async {
      final plaintext = List<int>.filled(128, 5);
      final aad = Uint8List.fromList(List<int>.filled(32, 7)); // Non-empty AAD

      // Encrypt with AAD
      final encryptor = ChaCha20Poly1305Encryptor(
        key: key,
        nonce: nonce,
        aad: aad,
      );

      final encryptedData = (await Stream.fromIterable([plaintext])
          .transform(encryptor)
          .expand((chunk) => chunk)
          .toList());

      // Decrypt with AAD
      final decryptor = ChaCha20Poly1305Decryptor(
        key: key,
        nonce: nonce,
        aad: aad, // Same AAD as encryption
      );

      final decryptedData = (await Stream.fromIterable([encryptedData])
              .transform(decryptor)
              .expand((chunk) => chunk)
              .toList())
          .toUint8List();

      expect(decryptedData, equals(plaintext));
    });

    test('handles memory efficiently with large streams', () async {
      final chunkSize = 1024 * 1024; // 1MB chunks
      final numberOfChunks = 10;

      final inputStream = Stream.periodic(Duration(milliseconds: 100), (i) {
        return List<int>.filled(chunkSize, i % 256);
      }).take(numberOfChunks);

      final encryptor = ChaCha20Poly1305Encryptor(
        key: FastCrypt.generateKey(),
        nonce: FastCrypt.generateNonce(),
      );

      var totalBytesProcessed = 0;
      await for (final chunk in inputStream.transform(encryptor)) {
        totalBytesProcessed += chunk.length;
      }

      expect(totalBytesProcessed, greaterThan(0));
    });
  });

  group('Padding Tests', () {
    late Uint8List key;
    late Uint8List nonce;

    setUp(() {
      key = Uint8List.fromList(List<int>.filled(32, 1));
      nonce = Uint8List.fromList(List<int>.filled(12, 2));
    });

    test('encryption with data requiring padding', () async {
      final encryptor = ChaCha20Poly1305Encryptor(
        key: key,
        nonce: nonce,
      );

      // Create data with length not multiple of 16 (e.g., 100 bytes)
      final inputData = List<int>.filled(100, 3);
      final inputStream = Stream.fromIterable([inputData]);
      final outputStream = inputStream.transform(encryptor);

      final result = await outputStream.toList();
      expect(result.length, equals(2)); // encrypted chunk and tag
      expect(result[0].length, equals(100));
      expect(result[1].length, equals(16)); // tag length
    });

    test('decryption with data requiring padding', () async {
      // First encrypt data that needs padding
      final plaintext = List<int>.filled(100, 3); // 100 is not multiple of 16

      final encryptor = ChaCha20Poly1305Encryptor(
        key: key,
        nonce: nonce,
      );

      final encryptedData = (await Stream.fromIterable([plaintext])
          .transform(encryptor)
          .expand((chunk) => chunk)
          .toList());

      // Then decrypt
      final decryptor = ChaCha20Poly1305Decryptor(
        key: key,
        nonce: nonce,
      );

      final decryptedData = (await Stream.fromIterable([encryptedData])
          .transform(decryptor)
          .expand((chunk) => chunk)
          .toList());

      expect(decryptedData, equals(plaintext));
    });

    test('encryption with exact block size', () async {
      final encryptor = ChaCha20Poly1305Encryptor(
        key: key,
        nonce: nonce,
      );

      // Create data with length exactly multiple of 16 (e.g., 96 bytes)
      final inputData = List<int>.filled(96, 3);
      final inputStream = Stream.fromIterable([inputData]);
      final outputStream = inputStream.transform(encryptor);

      final result = await outputStream.toList();
      expect(result.length, equals(2));
      expect(result[0].length, equals(96));
      expect(result[1].length, equals(16)); // tag length
    });
  });

  group('Large Chunk and Partial Processing Tests', () {
    late Uint8List key;
    late Uint8List nonce;

    setUp(() {
      key = Uint8List.fromList(List<int>.filled(32, 1));
      nonce = Uint8List.fromList(List<int>.filled(12, 2));
    });

    test('decryption with chunk larger than chunkSize and remaining data',
        () async {
      // Create encryptor with small chunk size for testing
      final encryptor = ChaCha20Poly1305Encryptor(
        key: key,
        nonce: nonce,
        chunkSize: 1024, // Small chunk size for testing
      );

      // Create large input data (larger than chunk size)
      final plaintext = List<int>.filled(2000, 3);

      // Encrypt the data
      final encryptedData = (await Stream.fromIterable([plaintext])
          .transform(encryptor)
          .expand((chunk) => chunk)
          .toList());

      // Create decryptor with small chunk size
      final decryptor = ChaCha20Poly1305Decryptor(
        key: key,
        nonce: nonce,
        chunkSize: 1024, // Small chunk size for testing
      );

      // Split the encrypted data into multiple chunks to simulate streaming
      // This will force the decryptor to handle partial blocks and remaining data
      final firstChunkSize =
          1500; // Larger than chunkSize but smaller than total
      final firstChunk = encryptedData.sublist(0, firstChunkSize);
      final secondChunk = encryptedData.sublist(firstChunkSize);

      final inputStream = Stream.fromIterable([firstChunk, secondChunk]);

      final decryptedData = await inputStream
          .transform(decryptor)
          .expand((chunk) => chunk)
          .toList();

      expect(decryptedData, equals(plaintext));
    });

    test('encryption stream with empty chunks', () async {
      final encryptor = ChaCha20Poly1305Encryptor(
        key: FastCrypt.generateKey(),
        nonce: FastCrypt.generateNonce(),
      );

      final inputStream = Stream.fromIterable(<List<int>>[
        [],
        [],
        [1, 2, 3],
        [],
      ]);
      final outputStream = inputStream.transform(encryptor);
      final result = await outputStream.toList();

      expect(result.length, equals(2)); // encrypted data and tag
      expect(result[0].length, equals(3)); // only non-empty chunk
      expect(result[1].length, equals(16)); // tag length
    });

    test('decryption stream with fragmented input', () async {
      final plaintext = List<int>.filled(100, 5);
      final key = FastCrypt.generateKey();
      final nonce = FastCrypt.generateNonce();

      // First encrypt normally
      final encrypted = (await Stream.fromIterable([plaintext])
          .transform(ChaCha20Poly1305Encryptor(
            key: key,
            nonce: nonce,
          ))
          .expand((chunk) => chunk)
          .toList());

      // Then decrypt with fragmented input
      final fragments = <List<int>>[];
      for (var i = 0; i < encrypted.length; i += 10) {
        fragments.add(encrypted.sublist(
            i, i + 10 > encrypted.length ? encrypted.length : i + 10));
      }

      final decrypted = (await Stream.fromIterable(fragments)
              .transform(ChaCha20Poly1305Decryptor(
                key: key,
                nonce: nonce,
              ))
              .expand((chunk) => chunk)
              .toList())
          .toUint8List();

      expect(decrypted, equals(plaintext));
    });
  });

  group('Key and Nonce Generation Edge Cases', () {
    test('generateKey returns different keys on subsequent calls', () {
      final key1 = FastCrypt.generateKey();
      final key2 = FastCrypt.generateKey();
      expect(key1, isNot(equals(key2)));
    });

    test('generateNonce returns different nonces on subsequent calls', () {
      final nonce1 = FastCrypt.generateNonce();
      final nonce2 = FastCrypt.generateNonce();
      expect(nonce1, isNot(equals(nonce2)));
    });
  });

  group('Stress Tests', () {
    test('encryption/decryption with very small data (1 byte)', () {
      final plaintext = Uint8List.fromList([0x42]);
      final encrypted = fastCrypt.encryptBytes(plaintext);
      final decrypted = fastCrypt.decryptBytes(
        ciphertext: encrypted.ciphertext,
        tag: encrypted.tag,
        key: encrypted.key,
        nonce: encrypted.nonce,
      );
      expect(decrypted, equals(plaintext));
    });

    test('encryption/decryption with prime-sized data', () {
      final plaintext = List<int>.generate(997, (i) => i % 256);
      final encrypted = fastCrypt.encryptBytes(Uint8List.fromList(plaintext));
      final decrypted = fastCrypt.decryptBytes(
        ciphertext: encrypted.ciphertext,
        tag: encrypted.tag,
        key: encrypted.key,
        nonce: encrypted.nonce,
      );
      expect(decrypted, equals(plaintext));
    });
  });

  group('Error Handling Tests', () {
    test('decryption with truncated ciphertext fails', () {
      final plaintext = utf8.encode('Test message');
      final encrypted = fastCrypt.encryptBytes(plaintext);
      final truncatedCiphertext =
          encrypted.ciphertext.sublist(0, encrypted.ciphertext.length - 1);

      expect(
        () => fastCrypt.decryptBytes(
          ciphertext: truncatedCiphertext,
          tag: encrypted.tag,
          key: encrypted.key,
          nonce: encrypted.nonce,
        ),
        throwsA(isA<AuthenticationException>()),
      );
    });
  });

  group('FastCrypt text encryption/decryption', () {
    late FastCrypt fastCrypt;

    setUp(() {
      fastCrypt = FastCrypt();
    });

    test('should encrypt and decrypt text correctly', () {
      final plaintext = 'Hello, World!';
      final encrypted = fastCrypt.encryptText(plaintext);
      final decrypted = fastCrypt.decryptText(encrypted);

      expect(decrypted, equals(plaintext));
    });

    test('should encrypt and decrypt text async correctly', () async {
      final plaintext = 'Hello, World!';
      final encrypted = await fastCrypt.encryptTextAsync(plaintext);
      final decrypted = await fastCrypt.decryptTextAsync(encrypted);

      expect(decrypted, equals(plaintext));
    });

    test('should handle empty string', () {
      final plaintext = '';
      final encrypted = fastCrypt.encryptText(plaintext);
      final decrypted = fastCrypt.decryptText(encrypted);

      expect(decrypted, equals(plaintext));
    });

    test('should handle unicode characters', () {
      final plaintext = '안녕하세요 👋 こんにちは';
      final encrypted = fastCrypt.encryptText(plaintext);
      final decrypted = fastCrypt.decryptText(encrypted);

      expect(decrypted, equals(plaintext));
    });

    test('should handle long text', () {
      final plaintext = 'a' * 10000;
      final encrypted = fastCrypt.encryptText(plaintext);
      final decrypted = fastCrypt.decryptText(encrypted);

      expect(decrypted, equals(plaintext));
    });

    // test('should throw FormatException for invalid base64', () {
    //   expect(
    //     () => fastCrypt.decryptText(EncryptedString(
    //         encryptedTextBytes: Uint8List(0),
    //         encryptionDataBytes: Uint8List(0))),
    //     throwsFormatException,
    //   );
    // });

    test('different encryptions of same text should decrypt to same result',
        () {
      final plaintext = 'Hello, World!';
      final encrypted1 = fastCrypt.encryptText(plaintext);
      final encrypted2 = fastCrypt.encryptText(plaintext);

      expect(encrypted1,
          isNot(equals(encrypted2))); // Different due to random key/nonce

      // Decrypt both and verify they match the original plaintext
      expect(fastCrypt.decryptText(encrypted1), equals(plaintext));
      expect(fastCrypt.decryptText(encrypted2), equals(plaintext));
    });

    group('EncryptedString validation', () {
      test('should throw ArgumentError for invalid key length', () {
        final invalidKey =
            Uint8List.fromList(List<int>.filled(31, 0)); // Wrong length
        final validNonce = Uint8List.fromList(List<int>.filled(12, 0));
        final validTag = Uint8List.fromList(List<int>.filled(16, 0));

        expect(
          () => EncryptedString.fromEncryptedData(EncryptedData(
            ciphertext: Uint8List.fromList([1, 2, 3]),
            key: invalidKey,
            nonce: validNonce,
            tag: validTag,
            aad: Uint8List.fromList([]),
          )),
          throwsA(isA<ArgumentError>().having(
            (e) => e.message,
            'message',
            'Invalid key length',
          )),
        );
      });

      test('should throw ArgumentError for invalid nonce length', () {
        final validKey = Uint8List.fromList(List<int>.filled(32, 0));
        final invalidNonce =
            Uint8List.fromList(List<int>.filled(11, 0)); // Wrong length
        final validTag = Uint8List.fromList(List<int>.filled(16, 0));

        expect(
          () => EncryptedString.fromEncryptedData(EncryptedData(
            ciphertext: Uint8List.fromList([1, 2, 3]),
            key: validKey,
            nonce: invalidNonce,
            tag: validTag,
            aad: Uint8List.fromList([]),
          )),
          throwsA(isA<ArgumentError>().having(
            (e) => e.message,
            'message',
            'Invalid nonce length',
          )),
        );
      });

      test('should throw ArgumentError for invalid tag length', () {
        final validKey = Uint8List.fromList(List<int>.filled(32, 0));
        final validNonce = Uint8List.fromList(List<int>.filled(12, 0));
        final invalidTag =
            Uint8List.fromList(List<int>.filled(15, 0)); // Wrong length

        expect(
          () => EncryptedString.fromEncryptedData(EncryptedData(
            ciphertext: Uint8List.fromList([1, 2, 3]),
            key: validKey,
            nonce: validNonce,
            tag: invalidTag,
            aad: Uint8List.fromList([]),
          )),
          throwsA(isA<ArgumentError>().having(
            (e) => e.message,
            'message',
            'Invalid tag length',
          )),
        );
      });
    });

    // group('EncryptedString.from factory', () {
    //   test('should throw FormatException for invalid encryption data length',
    //       () {
    //     final tooShortData =
    //         base64.encode(List<int>.filled(59, 0)); // Less than key+nonce+tag

    //     expect(
    //       () => EncryptedString.from('validBase64==', tooShortData),
    //       throwsA(isA<FormatException>().having(
    //         (e) => e.message,
    //         'message',
    //         'Invalid encryption data length',
    //       )),
    //     );
    //   });

    //   test('should validate reconstructed data', () {
    //     final invalidBase64 = 'not@valid@base64';

    //     expect(
    //       () => EncryptedString.from(invalidBase64, invalidBase64),
    //       throwsFormatException,
    //     );
    //   });
    // });

    // test('equality operator should compare all fields', () {
    //   final empty = Uint8List(0);
    //   final data1 = EncryptedString(
    //     encryptedTextBytes: empty,
    //     encryptionDataBytes: empty,
    //   );

    //   final data2 = EncryptedString(
    //     encryptedTextBytes: empty,
    //     encryptionDataBytes: empty,
    //   );

    //   final data3 = EncryptedString(
    //     encryptedTextBytes: Uint8List.fromList([1, 2, 3]),
    //     encryptionDataBytes: empty,
    //   );

    //   expect(data1, equals(data2));
    //   expect(data1, isNot(equals(data3)));
    // });

    // test('hashCode should be consistent with equals', () {
    //   final text = Uint8List.fromList([1, 2, 3]);
    //   final data = Uint8List.fromList([4, 5, 6]);

    //   final data1 = EncryptedString(
    //     encryptedTextBytes: text,
    //     encryptionDataBytes: data,
    //   );

    //   final data2 = EncryptedString(
    //     encryptedTextBytes: text,
    //     encryptionDataBytes: data,
    //   );

    //   expect(data1.hashCode, equals(data2.hashCode));
    // });

    group('Key and nonce generation', () {
      test('generateKey should create 32-byte key', () {
        final key = FastCrypt.generateKey();
        expect(key.length, equals(32));
      });

      test('generateNonce should create 12-byte nonce', () {
        final nonce = FastCrypt.generateNonce();
        expect(nonce.length, equals(12));
      });

      test('generated keys should be different', () {
        final key1 = FastCrypt.generateKey();
        final key2 = FastCrypt.generateKey();
        expect(key1, isNot(equals(key2)));
      });

      test('generated nonces should be different', () {
        final nonce1 = FastCrypt.generateNonce();
        final nonce2 = FastCrypt.generateNonce();
        expect(nonce1, isNot(equals(nonce2)));
      });
    });

    group('Performance Tests', () {
      test('handles large data efficiently', () {
        final largeData =
            List<int>.generate(1024 * 1024 * 5, (i) => i % 256); // 5MB
        final stopwatch = Stopwatch()..start();

        final encrypted = fastCrypt.encryptBytes(Uint8List.fromList(largeData));
        final encryptionTime = stopwatch.elapsedMilliseconds;

        stopwatch.reset();
        final decrypted = fastCrypt.decryptBytes(
          ciphertext: encrypted.ciphertext,
          tag: encrypted.tag,
          key: encrypted.key,
          nonce: encrypted.nonce,
        );
        final decryptionTime = stopwatch.elapsedMilliseconds;

        expect(decrypted, equals(largeData));
        expect(
            encryptionTime, lessThan(1000)); // Should complete within 1 second
        expect(decryptionTime, lessThan(1000));
      });
    });

    group('Concurrency Tests', () {
      test('handles multiple concurrent operations', () async {
        final futures = List.generate(100, (i) async {
          final text = 'Test message $i';
          final encrypted = fastCrypt.encryptText(text);
          final decrypted = fastCrypt.decryptText(encrypted);
          return decrypted;
        });

        final results = await Future.wait(futures);
        for (var i = 0; i < results.length; i++) {
          expect(results[i], equals('Test message $i'));
        }
      });
    });

    group('Random Input Tests', () {
      test('handles random length inputs', () {
        final random = Random();
        for (var i = 0; i < 1000; i++) {
          final length = random.nextInt(1000);
          final data = List<int>.generate(length, (i) => random.nextInt(256));

          final encrypted = fastCrypt.encryptBytes(Uint8List.fromList(data));
          final decrypted = fastCrypt.decryptBytes(
            ciphertext: encrypted.ciphertext,
            tag: encrypted.tag,
            key: encrypted.key,
            nonce: encrypted.nonce,
          );

          expect(decrypted, equals(data));
        }
      });
    });

    test('AEAD ChaCha20-Poly1305 Test Vector', () async {
      final fastCrypt = FastCrypt();

      final key =
          "41eb6927d73a8f265f5f85cc6973eaca914bd184061ed00c4d1e1f09c41f531d";
      final nonce = "182c69df17ec6da29790dc7d";
      final input = "Hello, this is a secret message!";

      // Perform encryption
      final encryptedData = fastCrypt.encryptString(
        input,
        key: hexDecode(key),
        nonce: hexDecode(nonce),
      );

      final encryptDataAsync = await fastCrypt.encryptStringAsync(
        input,
        key: hexDecode(key),
        nonce: hexDecode(nonce),
      );

      expect(encryptedData.ciphertext, encryptDataAsync.ciphertext);
      expect(encryptedData.tag, encryptDataAsync.tag);

      final expectedCipherText =
          "f42855d50ca908dd9a287774f10f20792d36db8363d0c954a77b046d9dbb445f";
      final expectedTag = "c593bdcab3605ba43c31773f63001ee0";

      final expectedCyperTextBytes = hexDecode(expectedCipherText);
      final expectedTagBytes = hexDecode(expectedTag);

      // Verify if encryption matches the test vector
      expect(encryptedData.ciphertext, equals(expectedCyperTextBytes));
      expect(encryptedData.tag, equals(expectedTagBytes));

      // Perform decryption
      final decryptedData = fastCrypt.decryptString(
        ciphertext: encryptedData.ciphertext,
        tag: encryptedData.tag,
        key: hexDecode(key),
        nonce: hexDecode(nonce),
      );

      final decryptDataAsync = await fastCrypt.decryptStringAsync(
        ciphertext: encryptedData.ciphertext,
        tag: encryptedData.tag,
        key: hexDecode(key),
        nonce: hexDecode(nonce),
      );

      expect(decryptedData, decryptDataAsync);

      // Verify if decryption matches the original input
      expect(decryptedData, input);
    });
  });
}

/// Helper function to decode hexadecimal strings into byte arrays
Uint8List hexDecode(String hexa) {
  final hex = hexa.replaceAll(' ', '');
  return Uint8List.fromList(List.generate(
    hex.length ~/ 2,
    (i) => int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16),
  ));
}

extension on List<int> {
  Uint8List toUint8List() => Uint8List.fromList(this);
}
