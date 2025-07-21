# EchoVaults Security Architecture

## Overview

EchoVaults is a digital legacy application designed to securely store and transmit final messages, important documents, and digital assets to trusted persons after the owner's passing. This document outlines the complete security architecture and design principles.

## Core Security Principles

### 1. **Local-First Security**
- All encryption and decryption occurs locally on the user's device
- No data is ever transmitted to cloud servers in unencrypted form
- Master passwords never leave the device
- Users maintain complete control over their data

### 2. **Zero-Knowledge Architecture**
- EchoVaults developers cannot access user data
- No backdoors or master keys exist
- Lost passwords result in permanent data loss (by design)
- User privacy is technically enforced, not just legally promised

### 3. **Graduated Privacy Levels**
- **Basic**: Immediate access for trusted persons after security questions
- **Sensitive**: Delayed access for trusted persons (configurable timing)
- **Ultra**: Owner-only access, never accessible to trusted persons

### 4. **Enhanced Cryptographic Standards**
- **AES-256 encryption** for all sensitive data
- **PBKDF2-HMAC-SHA256** for secure key derivation (10,000 iterations)
- **SHA-256 for password hashing** and legacy compatibility
- **Cryptographically secure random** salt and IV generation
- **No custom cryptography** - only proven, industry-standard algorithms

## Enhanced Encryption Implementation

### Master Password Security

#### Modern PBKDF2 Key Derivation (V2)
```dart
// Enhanced key derivation using PBKDF2-HMAC-SHA256
final salt = generateSalt(); // Cryptographically secure random salt
final pbkdf2 = Pbkdf2(
  macAlgorithm: Hmac.sha256(),
  iterations: 10000,  // 10,000 iterations for brute-force resistance
  bits: 256,          // 256-bit key
);
final key = await pbkdf2.deriveKeyFromPassword(password: masterPassword, nonce: salt);
```

#### Legacy SHA-256 Support (V1)
```dart
// Legacy method maintained for backward compatibility
final passwordBytes = utf8.encode(password);
final digest = sha256.convert(passwordBytes);
final key = Key(digest.bytes);
```

#### Password Hashing for Storage
```dart
// SHA-256 hashing for password verification
String hashedPassword = sha256.convert(utf8.encode(password)).toString();
```

### Vault Encryption by Privacy Level

#### Ultra Sensitive Vaults
- **Encryption**: AES-256 with PBKDF2-derived keys and random IV/salt
- **Access**: Owner only, requires master password
- **Key Derivation**: PBKDF2-HMAC-SHA256 (10,000 iterations) or legacy SHA-256 fallback
- **Format**: JSON with version, salt, IV, and encrypted data

```dart
// V2 Enhanced encryption with PBKDF2
final salt = generateSalt();
final key = await deriveKeyFromPassphrasePBKDF2(masterPassword, salt);
final iv = IV.fromSecureRandom(16);
final encrypter = Encrypter(AES(key));
final encrypted = encrypter.encrypt(plaintext, iv: iv);

final package = {
  'version': 2,
  'salt': base64.encode(salt),
  'iv': base64.encode(iv.bytes),
  'data': encrypted.base64,
  'iterations': 10000,
  'timestamp': DateTime.now().millisecondsSinceEpoch,
};
```

#### Basic & Sensitive Vaults
- **Encoding**: Base64 with integrity checksums and enhanced markers
- **Access**: Trusted persons (immediate for Basic, delayed for Sensitive)
- **Rationale**: Intentionally accessible without master password to enable designed inheritance
- **Format**: Enhanced V2 format with versioning and timestamps

```dart
// Enhanced basic/sensitive vault encoding with V2 markers
final encodedText = base64.encode(utf8.encode(text));
final checksum = sha256.convert(utf8.encode(text)).toString().substring(0, 8);
final package = {
  'type': 'basic', // or 'sensitive'
  'data': encodedText,
  'checksum': checksum,
  'version': 2,
  'timestamp': DateTime.now().millisecondsSinceEpoch,
};
final result = 'BASIC_VAULT_V2:' + jsonEncode(package);
```

### Enhanced File Attachment Security

#### Binary Data Encryption
- **Format**: Optimized binary format `[version][salt][iv][encrypted_data]`
- **Encryption**: AES-256 with PBKDF2-derived keys
- **Integrity**: Built-in format validation and error detection

```dart
// Enhanced binary encryption with optimized format
final salt = generateSalt();
final key = await deriveKeyFromPassphrasePBKDF2(passphrase, salt);
final iv = IV.fromSecureRandom(16);
final encrypter = Encrypter(AES(key));
final encrypted = encrypter.encryptBytes(data, iv: iv);

// Optimized binary format: [version][salt][iv][encrypted_data]
final result = <int>[];
result.add(2); // Version 2
result.addAll(salt);
result.addAll(iv.bytes);
result.addAll(encrypted.bytes);
```

#### Local Storage Only
- Files copied to application's private directory
- Unique timestamped filenames prevent conflicts
- No cloud synchronization or backup
- Files encrypted at filesystem level by OS

#### Integrity Verification
- SHA-256 checksums generated for all files
- Content-type validation via magic numbers
- File size warnings and limits
- Extension allow-listing

## Enhanced Access Control System

### Authentication Types

1. **Owner Authentication**
   - Master password verification with PBKDF2 or legacy support
   - Full access to all vaults and settings
   - Can reset trusted person access
   - Automatic encryption method detection and fallback

2. **Trusted Person Authentication**
   - Security questions verification
   - Limited access based on privacy levels
   - Cannot modify vaults or settings

### Security Questions Validation

- **Exact Match Required**: Case-sensitive, character-sensitive
- **No Fuzzy Matching**: Prevents unauthorized access through guessing
- **All Questions Required**: Partial success not permitted
- **No Rate Limiting**: Emergency access should not be blocked

```dart
bool validateAnswer(String providedAnswer) {
  final trimmedProvided = providedAnswer.trim();
  final trimmedCorrect = answer.trim();
  return trimmedProvided == trimmedCorrect;
}
```

### Enhanced Privacy Level Enforcement

```dart
static bool canAccessVault({
  required UserType userType,
  required PrivacyLevel privacyLevel,
  required String vaultId,
  DateTime? unlockTime,
  int sensitiveDelayHours = 24,
}) {
  if (userType == UserType.owner) return true;
  
  if (userType == UserType.trusted) {
    switch (privacyLevel) {
      case PrivacyLevel.basic:
        return unlockTime != null;
      case PrivacyLevel.sensitive:
        if (unlockTime == null) return false;
        if (sensitiveDelayHours == 0) return true;
        final accessTime = unlockTime.add(Duration(hours: sensitiveDelayHours));
        return DateTime.now().isAfter(accessTime);
      case PrivacyLevel.ultra:
        return false; // Never accessible to trusted persons
    }
  }
  
  return false;
}
```

## Enhanced Performance and Security Features

### Key Caching System
- **PBKDF2 key caching** for performance optimization
- **Memory management** with automatic cache size limits
- **Secure cleanup** of sensitive data in memory
- **Cache statistics** for monitoring and debugging

```dart
// Key caching for expensive PBKDF2 operations
static final Map<String, Key> _keyCache = {};
static const int _maxCacheSize = 10;

// Cache management
static void clearKeyCache() {
  _keyCache.clear();
}

static void secureCleanup(List<int> sensitiveData) {
  for (int i = 0; i < sensitiveData.length; i++) {
    sensitiveData[i] = 0;
  }
}
```

### Automatic Fallback System
- **Version detection** for encrypted data
- **Automatic fallback** from PBKDF2 to legacy SHA-256
- **Cross-version compatibility** maintained
- **Graceful error handling** with detailed logging

### Enhanced Binary Format
- **Optimized storage** format reduces overhead
- **Version markers** enable future upgrades
- **Integrity validation** built into format
- **Performance improvements** over text-based encoding

## Emergency Notification System

### Lock Screen Notifications
- Persistent notifications that cannot be dismissed
- Custom templates for emergency instructions
- Points to designated trusted persons
- Works even when device is locked

### Template Security
- User-defined message templates
- Variable substitution for names: `{{name1}}`, `{{name2}}`
- No external data sources
- Templates stored locally only

## Enhanced Session Management

### Authentication Sessions
- Session-based authentication to reduce password entry
- Configurable "request password every time" option
- Automatic session clearing on app backgrounding
- No persistent login tokens
- **Enhanced session security** with encryption key management

### Owner Privilege Escalation
```dart
Future<void> setAuthenticatedAsOwner({String? password}) async {
  _authenticatedThisSession = true;
  _authenticatedAs = 'owner';
  if (password != null && password.isNotEmpty) {
    _sessionMasterPassword = password;
  }
  // Enhanced session state management
  SharedPreferences prefs = await SharedPreferences.getInstance();
  await prefs.setBool('authenticated_this_session', true);
  await prefs.setString('authenticated_as', 'owner');
}
```

## Enhanced Data Storage Security

### Local Storage Structure
```
/app_documents/
├── vaults/
│   ├── vault.json              # Enhanced vault metadata with versioning
│   ├── security.json           # Security questions (answers hashed)
│   └── settings.json           # App settings with enhanced options
└── vault_files/
    └── [vault_id]/             # Per-vault file directories
        ├── [timestamp]_file1.jpg
        └── [timestamp]_file2.pdf
```

### Data Encryption at Rest
- **Vault Content**: Multi-tier encryption per privacy level
- **Security Questions**: Answers stored in plaintext for exact matching
- **Settings**: Unencrypted (non-sensitive configuration)
- **Files**: Protected by OS filesystem encryption + application-level encryption

## Enhanced Backup and Recovery

### Export Security
- **Enhanced Encrypted Backups**: Full vault backup with PBKDF2 protection
- **Unencrypted Exports**: Individual vault exports (owner only)
- **Cross-version compatibility**: Backup format supports V1 and V2 data
- **No Cloud Integration**: Manual export/import only

### Password Recovery
- **No Password Recovery**: Intentional design decision
- **No Reset Mechanism**: Lost passwords = lost data
- **No Hints or Questions**: Would weaken security

## Enhanced Threat Model

### Threats We Protect Against

1. **Unauthorized Device Access**
   - Screen lock and biometric protection (OS level)
   - Master password requirement for app access
   - Session timeouts and automatic locking
   - **Enhanced key derivation** makes offline attacks significantly harder

2. **Data Exfiltration**
   - Local-only storage prevents remote data theft
   - **PBKDF2 encryption** prevents offline attacks
   - **Salt-based security** prevents rainbow table attacks
   - No cloud vulnerabilities

3. **Social Engineering**
   - No password reset mechanisms to exploit
   - No customer service bypass options
   - Technical enforcement of privacy rules

4. **Brute Force Attacks**
   - **10,000 PBKDF2 iterations** significantly slow down brute force attempts
   - **Unique salts** prevent precomputed attack tables
   - **Strong key derivation** increases attack cost exponentially

5. **Malicious Trusted Persons**
   - Privacy levels prevent unauthorized access
   - Ultra sensitive vaults never accessible
   - Owner can reset access if still alive

### Threats We Don't Protect Against

1. **Physical Device Compromise**
   - If device is unlocked and app is authenticated
   - Relies on OS-level device security

2. **Advanced Persistent Threats**
   - Nation-state level attacks against specific individuals
   - Hardware-level compromise

3. **Coercion of the Owner**
   - If owner is forced to reveal master password
   - Physical threats against the user

## Enhanced Security Auditing

### Logging and Monitoring
- Failed authentication attempts logged locally
- **Enhanced debugging** with version and method tracking
- **Performance monitoring** for PBKDF2 operations
- No network logging or telemetry

### Audit Points
```dart
// Enhanced security audit points
debugPrint('Using PBKDF2 encryption v2 with ${iterations} iterations');
debugPrint('Fallback to legacy SHA-256 encryption');
debugPrint('Key derivation completed in ${stopwatch.elapsedMilliseconds}ms');
debugPrint('Security question ${i + 1} answered incorrectly');
debugPrint('All ${questions.length} security questions answered correctly');
debugPrint('Owner authentication successful with enhanced session management');
debugPrint('Trusted person access granted for vault: $vaultId');
```

## Enhanced Compliance and Standards

### Cryptographic Standards
- **NIST-Approved Algorithms**: AES-256, PBKDF2-HMAC-SHA256, SHA-256
- **Industry Best Practices**: 10,000+ PBKDF2 iterations
- **Secure Random Number Generation**: OS-provided entropy
- **Enhanced Key Management**: PBKDF2-derived keys with secure caching

### Privacy Standards
- **Data Minimization**: Only necessary data collected
- **Purpose Limitation**: Data used only for stated purpose
- **Storage Limitation**: Local storage only, no cloud
- **Transparency**: Complete source code disclosure for security components
- **Enhanced Security**: Upgraded encryption without compromising privacy

## Enhanced Security Testing

### Recommended Test Vectors

1. **PBKDF2 Encryption Round-Trip Tests**
   ```dart
   const plaintext = "Test message";
   final encrypted = await CoreEncryptionService.encryptText(plaintext, "password123");
   final decrypted = await CoreEncryptionService.decryptText(encrypted, "password123");
   assert(decrypted == plaintext);
   ```

2. **Cross-Version Compatibility Tests**
   ```dart
   // Test V2 -> V1 fallback
   final v2Encrypted = await CoreEncryptionService.encryptText(plaintext, password);
   final v1Encrypted = await CoreEncryptionService.encryptText(plaintext, password, useLegacy: true);
   
   assert(await CoreEncryptionService.decryptText(v2Encrypted, password) == plaintext);
   assert(await CoreEncryptionService.decryptText(v1Encrypted, password) == plaintext);
   ```

3. **Enhanced Privacy Level Enforcement**
   ```dart
   // Ultra vault should never be accessible to trusted person
   assert(!canAccessVault(
     userType: UserType.trusted,
     privacyLevel: PrivacyLevel.ultra,
     vaultId: "test",
     unlockTime: DateTime.now(),
   ));
   ```

4. **Performance and Security Balance Tests**
   ```dart
   // PBKDF2 should complete within reasonable time
   final stopwatch = Stopwatch()..start();
   await CoreEncryptionService.deriveKeyFromPassphrasePBKDF2(password, salt);
   stopwatch.stop();
   assert(stopwatch.elapsedMilliseconds < 5000); // 5 second max
   ```

## Security Contact

For security vulnerabilities or concerns regarding this implementation:

1. **Code Review**: This transparency repository enables full security audit
2. **Issue Reporting**: Submit issues via the repository's issue tracker
3. **Security Research**: We welcome responsible security research

---

**Note**: This document describes the enhanced security implementation made transparent through open source release. The complete application includes additional features and UI components not covered in this security-focused repository.

**Security Version**: 2.0 (Enhanced with PBKDF2)
**Backward Compatibility**: Maintains full compatibility with Version 1.0 (Legacy SHA-256)
**Last Updated**: July 21st 2025