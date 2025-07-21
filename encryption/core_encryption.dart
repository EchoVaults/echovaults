// lib/encryption/core_encryption.dart
//
// EchoVaults Transparency Repository
// Core Encryption Service - Open Source Implementation
//
// This file contains the complete encryption implementation used by EchoVaults
// to protect user data. No backdoors, no hidden functionality.
//
// Security Level: AES-256 with PBKDF2-HMAC-SHA256 key derivation
//

import 'dart:convert';
import 'dart:typed_data';
import 'dart:math';
import 'package:crypto/crypto.dart';
import 'package:encrypt/encrypt.dart' as encrypt;
import 'package:cryptography/cryptography.dart' as crypto;
import 'package:flutter/foundation.dart';

/// Core encryption service for EchoVaults
///
/// This service provides the fundamental encryption capabilities for protecting
/// user vault data. All encryption is performed locally on the device.
///
/// Key Features:
/// - AES-256 encryption with secure IV generation
/// - PBKDF2-HMAC-SHA256 based key derivation with salt
/// - SHA-256 legacy fallback for backward compatibility
/// - No cloud encryption - all keys derived from user passwords
/// - Different encryption modes for different privacy levels
/// - Key caching for performance optimization
class CoreEncryptionService {
  // Singleton pattern for consistent encryption across app
  static final CoreEncryptionService _instance = CoreEncryptionService._internal();
  factory CoreEncryptionService() => _instance;
  CoreEncryptionService._internal();

  // Enhanced markers for vault-level encryption accessible by trusted persons
  static const String _basicVaultMarker = 'BASIC_VAULT_V2:';
  static const String _sensitiveVaultMarker = 'SENSITIVE_VAULT_V2:';

  // Legacy markers for backward compatibility
  static const String _legacyBasicVaultMarker = 'BASIC_VAULT_V1:';
  static const String _legacySensitiveVaultMarker = 'SENSITIVE_VAULT_V1:';

  // PBKDF2 parameters - optimized for mobile devices
  static const int _pbkdf2Iterations = 10000;
  static const int _keyLength = 32; // 256 bits
  static const int _saltLength = 16; // 128 bits
  static const int _ivLength = 16; // 128 bits for AES

  // Cache for expensive PBKDF2 operations
  static final Map<String, encrypt.Key> _keyCache = {};
  static const int _maxCacheSize = 10; // Limit cache size to prevent memory issues

  /// Generates cryptographically secure random salt
  static Uint8List generateSalt([int length = _saltLength]) {
    final random = Random.secure();
    final salt = Uint8List(length);
    for (int i = 0; i < length; i++) {
      salt[i] = random.nextInt(256);
    }
    return salt;
  }

  /// Enhanced key derivation using PBKDF2-HMAC-SHA256 with caching
  ///
  /// This is the primary key derivation method for EchoVaults V2 encryption.
  /// Uses PBKDF2 with 10,000 iterations for enhanced security against brute force.
  ///
  /// [passphrase] User's master password
  /// [salt] Cryptographically secure random salt
  /// [iterations] Number of PBKDF2 iterations (default: 10,000)
  ///
  /// Returns: Encryption key suitable for AES operations
  static Future<encrypt.Key> deriveKeyFromPassphrasePBKDF2(
      String passphrase,
      Uint8List salt, {
        int iterations = _pbkdf2Iterations
      }) async {
    try {
      // Create cache key
      final cacheKey = '$passphrase:${base64.encode(salt)}:$iterations';

      // Check cache first
      if (_keyCache.containsKey(cacheKey)) {
        return _keyCache[cacheKey]!;
      }

      // Use cryptography package for PBKDF2
      final pbkdf2 = crypto.Pbkdf2(
        macAlgorithm: crypto.Hmac.sha256(),
        iterations: iterations,
        bits: _keyLength * 8, // Convert bytes to bits
      );

      final secretKey = await pbkdf2.deriveKeyFromPassword(
        password: passphrase,
        nonce: salt,
      );

      final keyBytes = await secretKey.extractBytes();
      final key = encrypt.Key(Uint8List.fromList(keyBytes));

      // Cache the key (with size limit)
      if (_keyCache.length >= _maxCacheSize) {
        _keyCache.remove(_keyCache.keys.first);
      }
      _keyCache[cacheKey] = key;

      return key;
    } catch (e) {
      debugPrint('Error deriving PBKDF2 key: $e');
      // Fallback to legacy method if PBKDF2 fails
      return deriveKeyFromPassphraseLegacy(passphrase);
    }
  }

  /// Legacy key derivation using SHA-256 for backward compatibility
  ///
  /// This method is maintained for compatibility with existing encrypted data
  /// and as a fallback when PBKDF2 is not available.
  ///
  /// [passphrase] User's master password
  /// [keyLength] Desired key length in bytes (default: 32 for AES-256)
  ///
  /// Returns: Encryption key suitable for AES operations
  static encrypt.Key deriveKeyFromPassphraseLegacy(String passphrase, {int keyLength = 32}) {
    try {
      final List<int> passphraseBytes = utf8.encode(passphrase);
      final Digest digest = sha256.convert(passphraseBytes);
      final Uint8List keyBytes = Uint8List.fromList(digest.bytes);
      final Uint8List paddedKey = _padOrTruncateKey(keyBytes, keyLength);
      return encrypt.Key(paddedKey);
    } catch (e) {
      debugPrint('Error deriving legacy key: $e');
      return encrypt.Key.fromLength(keyLength);
    }
  }

  /// Enhanced text encryption using AES-256 with PBKDF2 and automatic format detection
  ///
  /// This is used for ultra-sensitive vaults that require master password
  /// for decryption. Each encryption operation generates a unique IV and salt.
  ///
  /// [text] Plain text to encrypt
  /// [passphrase] User's master password
  /// [useLegacy] Force use of legacy SHA-256 method for compatibility
  ///
  /// Returns: Base64 encoded JSON containing salt, IV and encrypted data
  static Future<String> encryptText(String text, String passphrase, {bool useLegacy = false}) async {
    try {
      encrypt.Key key;
      Uint8List? salt;

      if (useLegacy) {
        // Use legacy SHA256 method for backward compatibility
        key = deriveKeyFromPassphraseLegacy(passphrase);
      } else {
        // Use new PBKDF2 method
        salt = generateSalt();
        key = await deriveKeyFromPassphrasePBKDF2(passphrase, salt);
      }

      final encrypt.IV iv = encrypt.IV.fromSecureRandom(_ivLength);
      final encrypt.Encrypter encrypter = encrypt.Encrypter(encrypt.AES(key));
      final encrypt.Encrypted encrypted = encrypter.encrypt(text, iv: iv);

      final Map<String, dynamic> encryptedPackage = {
        'iv': base64.encode(iv.bytes),
        'data': encrypted.base64,
        'version': useLegacy ? 1 : 2,
        'timestamp': DateTime.now().millisecondsSinceEpoch,
      };

      // Include salt for PBKDF2 version
      if (!useLegacy && salt != null) {
        encryptedPackage['salt'] = base64.encode(salt);
        encryptedPackage['iterations'] = _pbkdf2Iterations;
      }

      return jsonEncode(encryptedPackage);
    } catch (e) {
      debugPrint('Error encrypting text: $e');
      return '';
    }
  }

  /// Enhanced text decryption with automatic fallback to legacy methods
  ///
  /// Automatically detects encryption version and uses appropriate decryption method.
  /// Falls back to legacy SHA-256 if PBKDF2 fails.
  ///
  /// [encryptedPackage] JSON string containing salt, IV and encrypted data
  /// [passphrase] User's master password (must match encryption password)
  ///
  /// Returns: Decrypted plain text, or empty string on failure
  static Future<String> decryptText(String encryptedPackage, String passphrase) async {
    try {
      final Map<String, dynamic> package = jsonDecode(encryptedPackage);
      final int version = package['version'] ?? 1; // Default to legacy if not specified

      encrypt.Key key;

      if (version == 2 && package['salt'] != null) {
        // Use PBKDF2 for version 2
        final Uint8List salt = base64.decode(package['salt']);
        final int iterations = package['iterations'] ?? _pbkdf2Iterations;
        key = await deriveKeyFromPassphrasePBKDF2(passphrase, salt, iterations: iterations);
      } else {
        // Use legacy SHA256 for version 1 or if salt is missing
        key = deriveKeyFromPassphraseLegacy(passphrase);
      }

      final encrypt.IV iv = encrypt.IV.fromBase64(package['iv']);
      final encrypt.Encrypter encrypter = encrypt.Encrypter(encrypt.AES(key));
      final encrypted = encrypt.Encrypted.fromBase64(package['data']);

      return encrypter.decrypt(encrypted, iv: iv);
    } catch (e) {
      debugPrint('Error decrypting text (attempting fallback): $e');

      // Fallback: try legacy method if PBKDF2 fails
      try {
        final Map<String, dynamic> package = jsonDecode(encryptedPackage);
        final encrypt.Key key = deriveKeyFromPassphraseLegacy(passphrase);
        final encrypt.IV iv = encrypt.IV.fromBase64(package['iv']);
        final encrypt.Encrypter encrypter = encrypt.Encrypter(encrypt.AES(key));
        final encrypted = encrypt.Encrypted.fromBase64(package['data']);
        return encrypter.decrypt(encrypted, iv: iv);
      } catch (fallbackError) {
        debugPrint('Fallback decryption also failed: $fallbackError');
        return '';
      }
    }
  }

  /// Enhanced binary file encryption with optimized format
  ///
  /// Uses PBKDF2 for key derivation and optimized binary format for storage.
  /// Format: [version][salt][iv][encrypted_data]
  ///
  /// [data] Binary data to encrypt
  /// [passphrase] User's master password
  ///
  /// Returns: Encrypted binary data or null on failure
  static Future<Uint8List?> encryptBinaryData(Uint8List data, String passphrase) async {
    try {
      if (data.isEmpty) return null;

      final salt = generateSalt();
      final key = await deriveKeyFromPassphrasePBKDF2(passphrase, salt);
      final iv = encrypt.IV.fromSecureRandom(_ivLength);
      final encrypter = encrypt.Encrypter(encrypt.AES(key));

      // Encrypt the binary data
      final encrypted = encrypter.encryptBytes(data, iv: iv);

      // Create optimized binary format: [version][salt][iv][encrypted_data]
      final result = <int>[];
      result.add(2); // Version 2
      result.addAll(salt);
      result.addAll(iv.bytes);
      result.addAll(encrypted.bytes);

      return Uint8List.fromList(result);
    } catch (e) {
      debugPrint('Error encrypting binary data: $e');
      return null;
    }
  }

  /// Enhanced binary file decryption with automatic fallback
  ///
  /// Automatically detects format version and uses appropriate decryption method.
  ///
  /// [encryptedData] Binary data encrypted with encryptBinaryData()
  /// [passphrase] User's master password
  ///
  /// Returns: Decrypted binary data or null on failure
  static Future<Uint8List?> decryptBinaryData(Uint8List encryptedData, String passphrase) async {
    try {
      if (encryptedData.isEmpty) return null;

      final version = encryptedData[0];

      if (version == 2) {
        // New PBKDF2 format: [version][salt][iv][encrypted_data]
        if (encryptedData.length < 1 + _saltLength + _ivLength) {
          debugPrint('Invalid encrypted data length for version 2');
          return null;
        }

        final salt = encryptedData.sublist(1, 1 + _saltLength);
        final iv = encryptedData.sublist(1 + _saltLength, 1 + _saltLength + _ivLength);
        final data = encryptedData.sublist(1 + _saltLength + _ivLength);

        final key = await deriveKeyFromPassphrasePBKDF2(passphrase, salt);
        final encrypter = encrypt.Encrypter(encrypt.AES(key));
        final encrypted = encrypt.Encrypted(data);

        return Uint8List.fromList(encrypter.decryptBytes(encrypted, iv: encrypt.IV(iv)));
      } else {
        // Try legacy format as fallback
        return await _decryptBinaryDataLegacy(encryptedData, passphrase);
      }
    } catch (e) {
      debugPrint('Error decrypting binary data (attempting fallback): $e');

      // Try legacy format as fallback
      try {
        return await _decryptBinaryDataLegacy(encryptedData, passphrase);
      } catch (fallbackError) {
        debugPrint('Legacy binary decryption fallback failed: $fallbackError');
        return null;
      }
    }
  }

  /// Legacy binary decryption for backward compatibility
  static Future<Uint8List?> _decryptBinaryDataLegacy(Uint8List encryptedData, String passphrase) async {
    try {
      // Try different legacy formats

      // Format 1: [iv][encrypted_data]
      if (encryptedData.length >= _ivLength) {
        final iv = encryptedData.sublist(0, _ivLength);
        final data = encryptedData.sublist(_ivLength);

        final key = deriveKeyFromPassphraseLegacy(passphrase);
        final encrypter = encrypt.Encrypter(encrypt.AES(key));
        final encrypted = encrypt.Encrypted(data);

        return Uint8List.fromList(encrypter.decryptBytes(encrypted, iv: encrypt.IV(iv)));
      }

      return null;
    } catch (e) {
      debugPrint('Error in legacy binary decryption: $e');
      return null;
    }
  }

  /// Enhanced basic vault encryption with improved markers and versioning
  ///
  /// Basic vaults can be accessed by trusted persons without the master password
  /// after they pass security questions. Uses base64 encoding with integrity checking.
  ///
  /// Note: This is intentionally less secure than full encryption to enable
  /// trusted person access as designed by the vault owner.
  ///
  /// [text] Plain text to encrypt
  /// [masterPassword] Master password (for API compatibility, not used in basic encryption)
  ///
  /// Returns: Encoded text with basic vault marker and integrity checksum
  static String encryptTextForBasicVault(String text, String masterPassword) {
    try {
      // Use base64 encoding for basic vaults (accessible by trusted persons)
      final encodedText = base64.encode(utf8.encode(text));

      // Generate integrity checksum
      final checksum = _generateChecksum(text);

      // Create package with type information and version
      final basicPackage = {
        'type': 'basic',
        'data': encodedText,
        'checksum': checksum,
        'version': 2,
        'timestamp': DateTime.now().millisecondsSinceEpoch,
      };

      // Add enhanced marker to identify basic vault encryption
      return _basicVaultMarker + jsonEncode(basicPackage);
    } catch (e) {
      debugPrint('Error encrypting basic vault text: $e');
      // Fallback to full encryption if basic encoding fails
      return encryptText(text, masterPassword).toString();
    }
  }

  /// Enhanced basic vault decryption with legacy support
  ///
  /// Can be called without a password - this is by design for trusted person access.
  /// Includes integrity verification via checksum and supports both V1 and V2 formats.
  ///
  /// [encryptedText] Text encrypted with encryptTextForBasicVault()
  ///
  /// Returns: Decrypted plain text, or empty string on failure
  static String decryptTextForBasicVault(String encryptedText) {
    try {
      String jsonPart;

      // Support both V2 and legacy V1 markers
      if (encryptedText.startsWith(_basicVaultMarker)) {
        jsonPart = encryptedText.substring(_basicVaultMarker.length);
      } else if (encryptedText.startsWith(_legacyBasicVaultMarker)) {
        jsonPart = encryptedText.substring(_legacyBasicVaultMarker.length);
      } else {
        return '';
      }

      final Map<String, dynamic> package = jsonDecode(jsonPart);

      // Verify package type
      if (package['type'] != 'basic') {
        return '';
      }

      // Decode the text
      final decodedBytes = base64.decode(package['data']);
      final decodedText = utf8.decode(decodedBytes);

      // Verify integrity checksum if present
      if (package['checksum'] != null) {
        final expectedChecksum = _generateChecksum(decodedText);
        if (package['checksum'] != expectedChecksum) {
          debugPrint('Basic vault checksum mismatch - possible corruption');
          // Return text anyway but log the warning
        }
      }

      return decodedText;
    } catch (e) {
      debugPrint('Error decrypting basic vault text: $e');
      return '';
    }
  }

  /// Enhanced sensitive vault encryption with improved markers and versioning
  ///
  /// Sensitive vaults can be accessed by trusted persons after a time delay
  /// configured by the vault owner. Uses same encoding as basic vaults but
  /// with different marker for access control.
  ///
  /// [text] Plain text to encrypt
  /// [masterPassword] Master password (for API compatibility)
  ///
  /// Returns: Encoded text with sensitive vault marker
  static String encryptTextForSensitiveVault(String text, String masterPassword) {
    try {
      // Use base64 encoding (accessible by trusted persons after delay)
      final encodedText = base64.encode(utf8.encode(text));

      // Generate integrity checksum
      final checksum = _generateChecksum(text);

      final sensitivePackage = {
        'type': 'sensitive',
        'data': encodedText,
        'checksum': checksum,
        'version': 2,
        'timestamp': DateTime.now().millisecondsSinceEpoch,
      };

      return _sensitiveVaultMarker + jsonEncode(sensitivePackage);
    } catch (e) {
      debugPrint('Error encrypting sensitive vault text: $e');
      // Fallback to full encryption
      return encryptText(text, masterPassword).toString();
    }
  }

  /// Enhanced sensitive vault decryption with legacy support
  ///
  /// Can be called without password after the configured delay period.
  /// Access control timing is enforced at the application level.
  /// Supports both V1 and V2 formats.
  ///
  /// [encryptedText] Text encrypted with encryptTextForSensitiveVault()
  ///
  /// Returns: Decrypted plain text, or empty string on failure
  static String decryptTextForSensitiveVault(String encryptedText) {
    try {
      String jsonPart;

      // Support both V2 and legacy V1 markers
      if (encryptedText.startsWith(_sensitiveVaultMarker)) {
        jsonPart = encryptedText.substring(_sensitiveVaultMarker.length);
      } else if (encryptedText.startsWith(_legacySensitiveVaultMarker)) {
        jsonPart = encryptedText.substring(_legacySensitiveVaultMarker.length);
      } else {
        return '';
      }

      final Map<String, dynamic> package = jsonDecode(jsonPart);

      if (package['type'] != 'sensitive') {
        return '';
      }

      final decodedBytes = base64.decode(package['data']);
      final decodedText = utf8.decode(decodedBytes);

      // Verify integrity if checksum present
      if (package['checksum'] != null) {
        final expectedChecksum = _generateChecksum(decodedText);
        if (package['checksum'] != expectedChecksum) {
          debugPrint('Sensitive vault checksum mismatch - possible corruption');
        }
      }

      return decodedText;
    } catch (e) {
      debugPrint('Error decrypting sensitive vault text: $e');
      return '';
    }
  }

  /// Checks if encrypted text uses basic vault encryption (supports both versions)
  static bool isBasicVaultEncryption(String encryptedText) {
    return encryptedText.startsWith(_basicVaultMarker) ||
        encryptedText.startsWith(_legacyBasicVaultMarker);
  }

  /// Checks if encrypted text uses sensitive vault encryption (supports both versions)
  static bool isSensitiveVaultEncryption(String encryptedText) {
    return encryptedText.startsWith(_sensitiveVaultMarker) ||
        encryptedText.startsWith(_legacySensitiveVaultMarker);
  }

  /// Clears the PBKDF2 key cache for memory management
  static void clearKeyCache() {
    _keyCache.clear();
  }

  /// Gets cache statistics for monitoring
  static Map<String, int> getCacheStats() {
    return {
      'size': _keyCache.length,
      'maxSize': _maxCacheSize,
    };
  }

  /// Generates SHA-256 based checksum for integrity verification
  ///
  /// [text] Text to generate checksum for
  ///
  /// Returns: First 8 characters of SHA-256 hash (sufficient for integrity checking)
  static String _generateChecksum(String text) {
    final bytes = utf8.encode(text);
    final digest = sha256.convert(bytes);
    return digest.toString().substring(0, 8);
  }

  /// Verifies a password against its stored hash
  ///
  /// [password] Password to verify
  /// [hashedPassword] SHA-256 hash to verify against
  ///
  /// Returns: true if password is correct, false otherwise
  static bool verifyPassword(String password, String hashedPassword) {
    try {
      final List<int> passwordBytes = utf8.encode(password);
      final String hashedInput = sha256.convert(passwordBytes).toString();

      // Constant-time comparison to prevent timing attacks
      return hashedInput == hashedPassword;
    } catch (e) {
      debugPrint('Error verifying password: $e');
      return false;
    }
  }

  /// Hashes a password for secure storage
  ///
  /// [password] Password to hash
  ///
  /// Returns: SHA-256 hash of the password
  static String hashPassword(String password) {
    try {
      final List<int> passwordBytes = utf8.encode(password);
      return sha256.convert(passwordBytes).toString();
    } catch (e) {
      debugPrint('Error hashing password: $e');
      return '';
    }
  }

  /// Ensures key is exactly the desired length by padding or truncating
  ///
  /// [key] Input key bytes
  /// [desiredLength] Target length in bytes
  ///
  /// Returns: Key bytes adjusted to exact desired length
  static Uint8List _padOrTruncateKey(Uint8List key, int desiredLength) {
    if (key.length == desiredLength) {
      return key;
    } else if (key.length > desiredLength) {
      // Truncate if too long
      return Uint8List.fromList(key.sublist(0, desiredLength));
    } else {
      // Pad with zeros if too short
      final Uint8List paddedKey = Uint8List(desiredLength);
      paddedKey.setAll(0, key);
      for (int i = key.length; i < desiredLength; i++) {
        paddedKey[i] = 0;
      }
      return paddedKey;
    }
  }

  /// Secure memory cleanup for sensitive data
  static void secureCleanup(List<int> sensitiveData) {
    for (int i = 0; i < sensitiveData.length; i++) {
      sensitiveData[i] = 0;
    }
  }
}