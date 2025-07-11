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

### 4. **Cryptographic Standards**
- AES-256 encryption for all sensitive data
- SHA-256 for password hashing and key derivation
- Cryptographically secure random IV generation
- No custom cryptography - only proven algorithms

## Encryption Implementation

### Master Password Security

```dart
// Password hashing for storage
String hashedPassword = sha256.convert(utf8.encode(password)).toString();

// Key derivation for encryption
Key encryptionKey = Key(sha256.convert(utf8.encode(password)).bytes);
```

### Vault Encryption by Privacy Level

#### Ultra Sensitive Vaults
- **Encryption**: AES-256 with random IV
- **Access**: Owner only, requires master password
- **Key Derivation**: Direct from master password via SHA-256

```dart
final key = deriveKeyFromPassphrase(masterPassword);
final iv = IV.fromSecureRandom(16);
final encrypter = Encrypter(AES(key));
final encrypted = encrypter.encrypt(plaintext, iv: iv);
```

#### Basic & Sensitive Vaults
- **Encoding**: Base64 with integrity checksums
- **Access**: Trusted persons (immediate for Basic, delayed for Sensitive)
- **Rationale**: Intentionally accessible without master password to enable designed inheritance

```dart
final encodedText = base64.encode(utf8.encode(text));
final checksum = sha256.convert(utf8.encode(text)).toString().substring(0, 8);
final package = {'data': encodedText, 'checksum': checksum};
```

### File Attachment Security

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

## Access Control System

### Authentication Types

1. **Owner Authentication**
   - Master password verification
   - Full access to all vaults and settings
   - Can reset trusted person access

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

### Privacy Level Enforcement

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

## Session Management

### Authentication Sessions
- Session-based authentication to reduce password entry
- Configurable "request password every time" option
- Automatic session clearing on app backgrounding
- No persistent login tokens

### Owner Privilege Escalation
```dart
Future<void> setAuthenticatedAsOwner({String? password}) async {
  _authenticatedThisSession = true;
  _authenticatedAs = 'owner';
  if (password != null && password.isNotEmpty) {
    _sessionMasterPassword = password;
  }
  // Save session state
  SharedPreferences prefs = await SharedPreferences.getInstance();
  await prefs.setBool('authenticated_this_session', true);
  await prefs.setString('authenticated_as', 'owner');
}
```

## Data Storage Security

### Local Storage Structure
```
/app_documents/
├── vaults/
│   ├── vault.json              # Encrypted vault metadata
│   ├── security.json           # Security questions (answers hashed)
│   └── settings.json           # App settings
└── vault_files/
    └── [vault_id]/             # Per-vault file directories
        ├── [timestamp]_file1.jpg
        └── [timestamp]_file2.pdf
```

### Data Encryption at Rest
- **Vault Content**: Encrypted per privacy level
- **Security Questions**: Answers stored in plaintext for exact matching
- **Settings**: Unencrypted (non-sensitive configuration)
- **Files**: Protected by OS filesystem encryption

## Backup and Recovery

### Export Security
- **Encrypted Backups**: Full vault backup with master password protection
- **Unencrypted Exports**: Individual vault exports (owner only)
- **No Cloud Integration**: Manual export/import only

### Password Recovery
- **No Password Recovery**: Intentional design decision
- **No Reset Mechanism**: Lost passwords = lost data
- **No Hints or Questions**: Would weaken security

## Threat Model

### Threats We Protect Against

1. **Unauthorized Device Access**
   - Screen lock and biometric protection (OS level)
   - Master password requirement for app access
   - Session timeouts and automatic locking

2. **Data Exfiltration**
   - Local-only storage prevents remote data theft
   - Encrypted storage prevents offline attacks
   - No cloud vulnerabilities

3. **Social Engineering**
   - No password reset mechanisms to exploit
   - No customer service bypass options
   - Technical enforcement of privacy rules

4. **Malicious Trusted Persons**
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

## Security Auditing

### Logging and Monitoring
- Failed authentication attempts logged locally
- No network logging or telemetry
- Debug logs contain no sensitive information

### Audit Points
```dart
// Example security audit points
debugPrint('Security question ${i + 1} answered incorrectly');
debugPrint('All ${questions.length} security questions answered correctly');
debugPrint('Owner authentication successful');
debugPrint('Trusted person access granted for vault: $vaultId');
```

## Compliance and Standards

### Cryptographic Standards
- **NIST-Approved Algorithms**: AES-256, SHA-256
- **Secure Random Number Generation**: OS-provided entropy
- **Key Management**: Derived from user passwords, never stored

### Privacy Standards
- **Data Minimization**: Only necessary data collected
- **Purpose Limitation**: Data used only for stated purpose
- **Storage Limitation**: Local storage only, no cloud
- **Transparency**: Complete source code disclosure for security components

## Security Testing

### Recommended Test Vectors

1. **Encryption Round-Trip Tests**
   ```dart
   final plaintext = "Test message";
   final encrypted = encryptText(plaintext, "password123");
   final decrypted = decryptText(encrypted, "password123");
   assert(decrypted == plaintext);
   ```

2. **Privacy Level Enforcement**
   ```dart
   // Ultra vault should never be accessible to trusted person
   assert(!canAccessVault(
     userType: UserType.trusted,
     privacyLevel: PrivacyLevel.ultra,
     vaultId: "test",
     unlockTime: DateTime.now(),
   ));
   ```

3. **Security Questions Validation**
   ```dart
   final question = SecurityQuestion(
     id: "1", 
     question: "Test?", 
     answer: "Correct"
   );
   assert(question.validateAnswer("Correct") == true);
   assert(question.validateAnswer("correct") == false);
   ```

## Security Contact

For security vulnerabilities or concerns regarding this implementation:

1. **Code Review**: This transparency repository enables full security audit
2. **Issue Reporting**: Submit issues via the repository's issue tracker
3. **Security Research**: We welcome responsible security research

---

**Note**: This document describes the security implementation made transparent through open source release. The complete application includes additional features and UI components not covered in this security-focused repository.