import 'dart:typed_data';

import '../core/constants.dart';

/// Represents encrypted data including ciphertext, key, tag, nonce, and additional authenticated data.
class EncryptedData {
  final List<int> ciphertext;
  final Uint8List key;
  final Uint8List tag;
  final Uint8List nonce;
  final Uint8List aad;

  const EncryptedData({
    required this.ciphertext,
    required this.key,
    required this.tag,
    required this.nonce,
    required this.aad,
  });

  /// Combines key, nonce, tag, and AAD into a single list of bytes.
  Uint8List get _cipherData => Uint8List.fromList([
        ...key,
        ...nonce,
        ...tag,
        ...aad,
      ]);

  @override
  String toString() {
    return 'EncryptedData(ciphertext: $ciphertext, key: $key, tag: $tag, nonce: $nonce, aad: $aad)';
  }
}

class EncryptedString extends EncryptedData {
  final bool isUtf8;
  const EncryptedString({
    required super.ciphertext,
    required super.key,
    required super.tag,
    required super.nonce,
    required super.aad,
    this.isUtf8 = false,
  });

  @override
  String toString() {
    return 'EncryptedString(ciphertext: $ciphertext, key: $key, tag: $tag, nonce: $nonce, aad: $aad, isUtf8: $isUtf8)';
  }

  List<int> get encryptedTextBytes => ciphertext;
  Uint8List get encryptionDataBytes => _cipherData;

  factory EncryptedString.fromEncryptedData(EncryptedData data,
      {bool isUtf8 = false}) {
    if (data.key.length != FastCryptContants.keyLength) {
      throw ArgumentError('Invalid key length');
    }
    if (data.nonce.length != FastCryptContants.nonceLength) {
      throw ArgumentError('Invalid nonce length');
    }
    if (data.tag.length != FastCryptContants.tagLength) {
      throw ArgumentError('Invalid tag length');
    }
    final cipherText = data.ciphertext;

    return EncryptedString(
      isUtf8: isUtf8,
      ciphertext: cipherText,
      key: data.key,
      tag: data.tag,
      nonce: data.nonce,
      aad: data.aad,
    );
  }

  EncryptedData toEncryptedData() {
    final bytes = encryptionDataBytes;
    final keyLength = FastCryptContants.keyLength;
    final nonceLength = FastCryptContants.nonceLength;
    final tagLength = FastCryptContants.tagLength;
    final totalLength = keyLength + nonceLength + tagLength;

    if (bytes.length < totalLength) {
      throw FormatException('Invalid encryption data length');
    }

    int start = 0;

    Uint8List extractBytes(int length) {
      final extracted = bytes.sublist(start, start + length);
      start += length;
      return extracted;
    }

    return EncryptedData(
      key: extractBytes(keyLength),
      nonce: extractBytes(nonceLength),
      tag: extractBytes(tagLength),
      aad: bytes.sublist(start),
      ciphertext: encryptedTextBytes,
    );
  }
}

class EncryptedBytes extends EncryptedData {
  const EncryptedBytes({
    required super.ciphertext,
    required super.key,
    required super.tag,
    required super.nonce,
    required super.aad,
  });

  @override
  String toString() {
    return 'EncryptedBytes(ciphertext: $ciphertext, key: $key, tag: $tag, nonce: $nonce, aad: $aad)';
  }
}
