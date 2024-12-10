import 'dart:math';
import 'dart:typed_data';

class Poly1305Mac {
  static final BigInt p = (BigInt.one << 130) - BigInt.from(5);
  static const int blockSize = 16;
  static final BigInt _accumulatorModulus = (BigInt.one << 128);

  final BigInt _r;
  final BigInt _s;
  final Uint8List _buffer;
  int _bufferIndex = 0;
  bool _finished = false;

  Poly1305Mac(Uint8List key)
      : _buffer = Uint8List(blockSize),
        _r = _leBytesToInteger(clampR(key.sublist(0, 16))),
        _s = _leBytesToInteger(key.sublist(16, 32));

  void update(List<int> data) {
    if (_finished) {
      throw StateError('Poly1305 has already been finished');
    }

    int offset = 0;
    int remaining = data.length;

    // Handle leftover data from previous update
    if (_bufferIndex > 0) {
      int toCopy = min(blockSize - _bufferIndex, remaining);
      _buffer.setRange(_bufferIndex, _bufferIndex + toCopy, data);
      _bufferIndex += toCopy;

      if (_bufferIndex == blockSize) {
        _processBlock(_buffer);
        _bufferIndex = 0;
      }

      offset += toCopy;
      remaining -= toCopy;
    }

    // Process full blocks directly from input
    while (remaining >= blockSize) {
      _processBlock(data.sublist(offset, offset + blockSize));
      offset += blockSize;
      remaining -= blockSize;
    }

    // Store remaining bytes in buffer
    if (remaining > 0) {
      _buffer.setRange(0, remaining, data, offset);
      _bufferIndex = remaining;
    }
  }

  Uint8List finish() {
    if (_finished) {
      throw StateError('Poly1305 has already been finished');
    }

    // Process final block if there's data in buffer
    if (_bufferIndex > 0) {
      _processBlock(_buffer.sublist(0, _bufferIndex));
    }

    _acc = (_acc + _s) % (_accumulatorModulus);
    _finished = true;

    return integerToLeBytes(_acc, 16);
  }

  BigInt _acc = BigInt.zero;

  void _processBlock(List<int> block) {
    BigInt n = _leBytesToInteger(block);

    if (block.length == blockSize) {
      n += (_accumulatorModulus);
    } else {
      n += (BigInt.one << (8 * block.length));
    }

    _acc = ((_acc + n) % p * _r) % p;
  }

  static Uint8List clampR(Uint8List result) {
    result[3] &= 15;
    result[7] &= 15;
    result[11] &= 15;
    result[15] &= 15;
    result[4] &= 252;
    result[8] &= 252;
    result[12] &= 252;
    return result;
  }

  static BigInt _leBytesToInteger(List<int> bytes) {
    BigInt result = BigInt.zero;
    for (int i = 0; i < bytes.length; i++) {
      result |= BigInt.from(bytes[i]) << (8 * i);
    }
    return result;
  }

  static Uint8List integerToLeBytes(BigInt number, int length) {
    var bytes = Uint8List(length);
    var temp = number;
    for (int i = 0; i < length; i++) {
      bytes[i] = (temp & BigInt.from(0xff)).toInt();
      temp = temp >> 8;
    }
    return bytes;
  }
}
