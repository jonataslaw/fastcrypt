import 'dart:async';
import 'dart:typed_data';

import '../algorithms/poly1305_mac.dart';
import '../core/constants.dart';
import '../core/utils.dart';
import '../exceptions/authentication_exception.dart';

/// Decrypts data using ChaCha20-Poly1305 without expecting the nonce in the input stream.
class ChaCha20Poly1305Decryptor
    extends StreamTransformerBase<List<int>, List<int>> {
  final Uint8List key;
  final Uint8List nonce;
  final Uint8List? aad;
  final int chunkSize;

  const ChaCha20Poly1305Decryptor({
    required this.key,
    required this.nonce,
    this.aad,
    this.chunkSize = 64 * 1024, // 64KB
  });

  @override
  Stream<List<int>> bind(Stream<List<int>> stream) async* {
    // Buffer to accumulate incoming data
    final List<List<int>> dataChunks = [];

    int totalDataLength = 0;

    // Read all chunks from the stream
    await for (List<int> chunk in stream) {
      dataChunks.add(chunk);
      totalDataLength += chunk.length;
    }

    // Concatenate all chunks
    final allData = List.filled(totalDataLength, 0);
    int offset = 0;
    for (var chunk in dataChunks) {
      allData.setRange(offset, offset + chunk.length, chunk);
      offset += chunk.length;
    }

    // Validate that the data has at least the authentication tag
    if (allData.length < FastCryptContants.tagLength) {
      throw ArgumentError(
          'Insufficient data: data length ${allData.length} is less than the minimum required length of ${FastCryptContants.tagLength} bytes (authentication tag).');
    }

    // Extract tag (last 16 bytes)
    int ciphertextLength = allData.length - FastCryptContants.tagLength;
    List<int> ciphertext = allData.sublist(0, ciphertextLength);
    List<int> tag = allData.sublist(ciphertextLength);

    // Initialize Poly1305 MAC
    Uint8List polyKey = poly1305KeyGen(key, nonce);
    Poly1305Mac mac = Poly1305Mac(polyKey);
    final Uint8List aad = this.aad ?? Uint8List(0);
    // Process AAD
    if (aad.isNotEmpty) {
      mac.update(aad);
      mac.update(padding(aad.length));
    }

    // Update MAC with ciphertext
    mac.update(ciphertext);

    // Process padding for ciphertext
    int ciphertextPaddingLength = (16 - (ciphertext.length % 16)) % 16;
    if (ciphertextPaddingLength > 0) {
      mac.update(Uint8List(ciphertextPaddingLength));
    }

    // Process lengths
    ByteData lengthBlock = ByteData(16)
      ..setUint64(0, aad.length, Endian.little)
      ..setUint64(8, ciphertext.length, Endian.little);

    mac.update(lengthBlock.buffer.asUint8List());

    // Compute expected tag
    Uint8List expectedTag = mac.finish();

    // Verify the authentication tag
    if (!constantTimeCompare(tag, expectedTag)) {
      throw AuthenticationException('Invalid authentication tag');
    }

    // Decrypt the ciphertext
    int counter = 1; // Starts from 1 as per specification
    List<int> plaintext = chacha20Encrypt(key, counter, nonce, ciphertext);

    // Yield decrypted data in chunks
    int offsetPlaintext = 0;
    int length = plaintext.length;

    while (offsetPlaintext < length) {
      int end = (offsetPlaintext + chunkSize <= length)
          ? offsetPlaintext + chunkSize
          : length;
      yield plaintext.sublist(offsetPlaintext, end);
      offsetPlaintext = end;
    }
  }
}
