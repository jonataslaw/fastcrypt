import 'dart:typed_data';

import '../algorithms/poly1305_mac.dart';

/// ChaCha20 block function.
Uint8List chacha20Block(Uint8List key, int counter, Uint8List nonce) {
  final state = Uint32List(16);

  // Constants
  state[0] = 0x61707865;
  state[1] = 0x3320646e;
  state[2] = 0x79622d32;
  state[3] = 0x6b206574;

  // Key
  final keyData = ByteData.sublistView(key);
  for (int i = 0; i < 8; i++) {
    state[4 + i] = keyData.getUint32(i * 4, Endian.little);
  }

  // Counter
  state[12] = counter;

  // Nonce
  final nonceData = ByteData.sublistView(nonce);
  for (int i = 0; i < 3; i++) {
    state[13 + i] = nonceData.getUint32(i * 4, Endian.little);
  }

  // Working state
  final workingState = Uint32List.fromList(state);

  // 20 rounds
  for (int i = 0; i < 10; i++) {
    // Column rounds
    quarterRound(workingState, 0, 4, 8, 12);
    quarterRound(workingState, 1, 5, 9, 13);
    quarterRound(workingState, 2, 6, 10, 14);
    quarterRound(workingState, 3, 7, 11, 15);
    // Diagonal rounds
    quarterRound(workingState, 0, 5, 10, 15);
    quarterRound(workingState, 1, 6, 11, 12);
    quarterRound(workingState, 2, 7, 8, 13);
    quarterRound(workingState, 3, 4, 9, 14);
  }

  // Add the original state to the working state
  final block = Uint8List(64);
  final blockData = ByteData.sublistView(block);
  for (int i = 0; i < 16; i++) {
    final value = (workingState[i] + state[i]) & 0xffffffff;
    blockData.setUint32(i * 4, value, Endian.little);
  }

  return block;
}

/// Performs a quarter round operation.
void quarterRound(Uint32List state, int a, int b, int c, int d) {
  state[a] = (state[a] + state[b]) & 0xffffffff;
  state[d] ^= state[a];
  state[d] = (state[d] << 16) | (state[d] >> 16);

  state[c] = (state[c] + state[d]) & 0xffffffff;
  state[b] ^= state[c];
  state[b] = (state[b] << 12) | (state[b] >> 20);

  state[a] = (state[a] + state[b]) & 0xffffffff;
  state[d] ^= state[a];
  state[d] = (state[d] << 8) | (state[d] >> 24);

  state[c] = (state[c] + state[d]) & 0xffffffff;
  state[b] ^= state[c];
  state[b] = (state[b] << 7) | (state[b] >> 25);
}

/// Generates the Poly1305 key using ChaCha20 with counter set to zero.
Uint8List poly1305KeyGen(Uint8List key, Uint8List nonce) {
  final block = chacha20Block(key, 0, nonce);
  return Uint8List.sublistView(block, 0, 32);
}

/// Pads the data to a multiple of 16 bytes.
Uint8List padding(int length) {
  int rem = length % 16;
  if (rem == 0) {
    return Uint8List(0);
  }
  int padLen = 16 - rem;
  return Uint8List(padLen);
}

/// Converts an integer to a Uint8List in little-endian format.
Uint8List _intToUint8List(int value, int length) {
  final bytes = Uint8List(length);
  final byteData = ByteData.sublistView(bytes);
  byteData.setUint64(0, value, Endian.little);
  return bytes;
}

/// Performs a constant-time comparison of two byte arrays.
bool constantTimeCompare(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  int result = 0;
  for (int i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }
  return result == 0;
}

/// Calculates the Poly1305 authentication tag for the given [ciphertext], [aad], and [polyKey].
Uint8List calculateTag(List<int> ciphertext, Uint8List aad, Uint8List polyKey) {
  // Initialize cipher

  final mac = Poly1305Mac(polyKey);

  // Compute authentication tag
  mac.update(aad);
  if (aad.isNotEmpty) {
    mac.update(padding(aad.length));
  }
  mac.update(ciphertext);
  if (ciphertext.isNotEmpty) {
    mac.update(padding(ciphertext.length));
  }
  mac.update(_intToUint8List(aad.length, 8));
  mac.update(_intToUint8List(ciphertext.length, 8));

  return mac.finish();
}

/// Encrypts or decrypts data using ChaCha20.
List<int> chacha20Encrypt(
  Uint8List key,
  int counter,
  Uint8List nonce,
  List<int> input,
) {
  final length = input.length;
  List<int> output =
      (input is Uint8List) ? Uint8List(length) : List.filled(length, 0);

  int numBlocks = (length + 63) ~/ 64;

  for (int blockNum = 0; blockNum < numBlocks; blockNum++) {
    final keyStreamBlock = chacha20Block(key, counter + blockNum, nonce);

    int start = blockNum * 64;
    int end = (start + 64 <= length) ? start + 64 : length;

    for (int i = start; i < end; i++) {
      output[i] = input[i] ^ keyStreamBlock[i - start];
    }
  }

  return output;
}
