```dart
import 'dart:async';
import 'dart:convert';
import 'dart:math';

import 'package:cryptography/cryptography.dart';
import 'package:fastcrypt/fastcrypt.dart';

class BenchmarkResult {
  final String name;
  final List<int> times;
  final Duration totalDuration;
  final int iterations;
  final int warmupIterations;

  BenchmarkResult({
    required this.name,
    required this.times,
    required this.totalDuration,
    required this.iterations,
    required this.warmupIterations,
  });

  double get average =>
      times.isEmpty ? 0 : times.reduce((a, b) => a + b) / times.length;
  int get min => times.isEmpty ? 0 : times.reduce((a, b) => a < b ? a : b);
  int get max => times.isEmpty ? 0 : times.reduce((a, b) => a > b ? a : b);

  double get median {
    if (times.isEmpty) return 0;
    final sorted = List<int>.from(times)..sort();
    final middle = sorted.length ~/ 2;
    if (sorted.length.isOdd) {
      return sorted[middle].toDouble();
    }
    return (sorted[middle - 1] + sorted[middle]) / 2;
  }

  double get standardDeviation {
    if (times.length <= 1) return 0;
    final mean = average;
    final squares = times.map((t) => pow(t - mean, 2));
    return sqrt(squares.reduce((a, b) => a + b) / (times.length - 1));
  }

  Map<String, dynamic> toJson() => {
        'name': name,
        'iterations': iterations,
        'warmupIterations': warmupIterations,
        'totalDurationMs': totalDuration.inMilliseconds,
        'statistics': {
          'averageUs': average,
          'medianUs': median,
          'minUs': min,
          'maxUs': max,
          'stdDevUs': standardDeviation,
        },
        'times': times,
      };
}

class Benchmark {
  final String name;
  final Future<void> Function() setup;
  final FutureOr<void> Function() run;
  final int iterations;
  final int warmupIterations;
  final Duration cooldown;
  final bool throwOnError;

  Benchmark({
    required this.name,
    required this.setup,
    required this.run,
    this.iterations = 100,
    this.warmupIterations = 10,
    this.cooldown = const Duration(milliseconds: 50),
    this.throwOnError = false,
  });

  Future<BenchmarkResult> execute() async {
    print('\nBenchmarking $name...');
    final totalStopwatch = Stopwatch()..start();

    try {
      await setup();

      // Warmup phase
      print('Warming up...');
      for (var i = 0; i < warmupIterations; i++) {
        await run();
        await Future.delayed(cooldown);
      }

      // Actual benchmark
      print('Running benchmark...');
      final stopwatch = Stopwatch();
      final times = <int>[];

      for (var i = 0; i < iterations; i++) {
        try {
          stopwatch.start();
          await run();
          stopwatch.stop();
          times.add(stopwatch.elapsedMicroseconds);
          stopwatch.reset();

          if (i % (iterations ~/ 10) == 0) {
            print('Progress: ${((i / iterations) * 100).toStringAsFixed(1)}%');
          }

          await Future.delayed(cooldown);
        } catch (e) {
          print('Error during iteration $i: $e');
          if (throwOnError) rethrow;
        }
      }

      totalStopwatch.stop();
      final result = BenchmarkResult(
        name: name,
        times: times,
        totalDuration: totalStopwatch.elapsed,
        iterations: iterations,
        warmupIterations: warmupIterations,
      );

      _printResults(result);
      return result;
    } catch (e) {
      print('Benchmark "$name" failed: $e');
      if (throwOnError) rethrow;
      return BenchmarkResult(
        name: name,
        times: [],
        totalDuration: totalStopwatch.elapsed,
        iterations: iterations,
        warmupIterations: warmupIterations,
      );
    }
  }

  void _printResults(BenchmarkResult result) {
    print('\nResults for $name:');
    print('Total duration: ${result.totalDuration.inMilliseconds}ms');
    print(
        'Iterations: ${result.iterations} (+ ${result.warmupIterations} warmup)');
    print('Average: ${result.average.toStringAsFixed(2)} µs');
    print('Median: ${result.median.toStringAsFixed(2)} µs');
    print('Min: ${result.min} µs');
    print('Max: ${result.max} µs');
    print(
        'Standard deviation: ${result.standardDeviation.toStringAsFixed(2)} µs');
  }
}

Future<void> main() async {
  final fastCrypt = FastCrypt();
  final chacha = Chacha20.poly1305Aead();

  final plaintext = utf8.encode('The quick brown fox jumps over the lazy dog');
  final fastCryptKey = FastCrypt.generateKey();
  final cryptographyKey = await chacha.newSecretKey();

  final fastCryptEncryptedData = fastCrypt.encryptBytes(
    plaintext,
    key: fastCryptKey,
    nonce: FastCrypt.generateNonce(),
  );

  final secretBox = await chacha.encrypt(
    plaintext,
    secretKey: cryptographyKey,
  );

  final results = [
    Benchmark(
      name: 'FastCrypt Encryption',
      setup: () async {},
      run: () {
        fastCrypt.encryptBytes(
          plaintext,
          key: fastCryptEncryptedData.key,
          nonce: fastCryptEncryptedData.nonce,
        );
      },
    ).execute(),
    Benchmark(
      name: 'FastCrypt Decryption',
      setup: () async {},
      run: () {
        fastCrypt.decryptBytes(
          ciphertext: fastCryptEncryptedData.ciphertext,
          tag: fastCryptEncryptedData.tag,
          key: fastCryptEncryptedData.key,
          nonce: fastCryptEncryptedData.nonce,
        );
      },
    ).execute(),
    Benchmark(
      name: 'Cryptography Encryption',
      setup: () async {},
      run: () async {
        await chacha.encrypt(
          plaintext,
          secretKey: cryptographyKey,
          nonce: secretBox.nonce,
        );
      },
    ).execute(),
    Benchmark(
      name: 'Cryptography Decryption',
      setup: () async {},
      run: () async {
        await chacha.decrypt(
          secretBox,
          secretKey: cryptographyKey,
        );
      },
    ).execute(),
  ];

  final resultsCalled = await Future.wait(results);

  // Print comparison summary
  print('\nComparison Summary:');
  for (final result in resultsCalled) {
    print('${result.name}:');
    print('  Median: ${result.median.toStringAsFixed(2)} µs');
    print('  Std Dev: ${result.standardDeviation.toStringAsFixed(2)} µs');
  }
}
```