import 'dart:async';
import 'dart:typed_data';

import '../algorithms/poly1305_mac.dart';
import '../core/utils.dart';

/// Encrypts data using ChaCha20-Poly1305 without including the nonce in the output stream.
class ChaCha20Poly1305Encryptor
    extends StreamTransformerBase<List<int>, List<int>> {
  final Uint8List key;
  final Uint8List nonce;
  final Uint8List? aad;
  final int chunkSize;

  const ChaCha20Poly1305Encryptor({
    required this.key,
    required this.nonce,
    this.aad,
    this.chunkSize = 64 * 1024, // 64KB
  });

  @override
  Stream<List<int>> bind(Stream<List<int>> stream) async* {
    // Initialize Poly1305
    Uint8List polyKey = poly1305KeyGen(key, nonce);
    Poly1305Mac mac = Poly1305Mac(polyKey);
    final Uint8List aad = this.aad ?? Uint8List(0);

    // Process AAD
    if (aad.isNotEmpty) {
      mac.update(aad);
      mac.update(padding(aad.length));
    }

    // Initialize counter for ChaCha20
    int counter = 1; // Starts from 1 as per specification

    int totalDataLength = 0;

    // Stream processing
    await for (List<int> chunk in stream) {
      if (chunk.isEmpty) continue; // Skip empty chunks

      // Encrypt chunk
      List<int> encryptedChunk = chacha20Encrypt(key, counter, nonce, chunk);

      // Update counter
      int numberOfBlocks = (encryptedChunk.length + 63) ~/ 64;
      counter += numberOfBlocks;

      // Update MAC with encrypted data
      mac.update(encryptedChunk);

      totalDataLength += encryptedChunk.length;

      // Yield encrypted chunk
      yield encryptedChunk;
    }

    // Process padding for ciphertext
    int ciphertextPaddingLength = (16 - (totalDataLength % 16)) % 16;
    if (ciphertextPaddingLength > 0) {
      mac.update(Uint8List(ciphertextPaddingLength));
    }

    // Process lengths
    ByteData lengthBlock = ByteData(16)
      ..setUint64(0, aad.length, Endian.little)
      ..setUint64(8, totalDataLength, Endian.little);

    mac.update(lengthBlock.buffer.asUint8List());

    // Compute tag
    Uint8List tag = mac.finish();

    // Yield tag
    yield tag;
  }
}