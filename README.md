# EchoVaults Transparency Repository

> **"Your last word should be heard only when it truly matters, and by those who truly matter."**

## What is EchoVaults?

EchoVaults is a digital legacy application that allows you to securely store messages, documents, and media for your loved ones to access after you're gone. Unlike a traditional will or note, EchoVaults gives you **granular control** over who can see what, and when.

This repository contains the **complete security and privacy implementation** of EchoVaults, made open source to build trust through transparency.

## Why Open Source the Security Layer?

When dealing with life-and-death matters, **trust cannot be built on promises alone**. It must be built on **verifiable technology**.

### What You Can Verify:
- **Enhanced Encryption Implementation**: See exactly how your data is protected with PBKDF2-HMAC-SHA256
- **Privacy Controls**: Verify how the three privacy levels work
- **Access Logic**: Understand who can see what, and when
- **No Backdoors**: Confirm there are no hidden access methods
- **Local-Only Storage**: Verify data never leaves your device
- **Cross-Version Compatibility**: Ensure your existing data remains accessible

### What We Keep Proprietary:
- **User Interface**: Our design and user experience
- **Trademarked Name**: EchoVaults as brand

## Repository Contents

### Core Security Components

#### [`lib/encryption/core_encryption.dart`](lib/encryption/core_encryption.dart)
The heart of EchoVaults security with **enhanced cryptographic protection**. Contains:
- **AES-256 encryption** with PBKDF2-HMAC-SHA256 key derivation
- **10,000 iteration PBKDF2** for brute-force resistance
- **Automatic salt generation** for each encryption operation
- **Key derivation caching** for performance optimization
- **Privacy-level specific encryption** (Basic, Sensitive, Ultra)
- **Cross-version compatibility** with automatic fallback
- **Password hashing and verification**

```dart
// Example: Enhanced Ultra vault encryption with PBKDF2 (owner-only)
final encrypted = await CoreEncryptionService.encryptText(content, masterPassword);

// Example: Basic vault encoding (accessible to trusted persons)
final encoded = CoreEncryptionService.encryptTextForBasicVault(content, masterPassword);

// Example: Binary file encryption with optimized format
final encryptedFile = await CoreEncryptionService.encryptBinaryData(fileData, masterPassword);
```

#### [`lib/security/privacy_levels.dart`](lib/security/privacy_levels.dart)
Implements the three-tier privacy system:
- **🟢 Basic**: Immediate access after security questions
- **🟡 Sensitive**: Delayed access (configurable: hours to years)
- **🔴 Ultra**: Owner-only, never accessible to trusted persons

#### [`lib/security/security_questions.dart`](lib/security/security_questions.dart)
Security questions validation logic:
- **Exact matching** (case-sensitive, no fuzzy matching)
- **All questions required** (no partial success)
- **Integrity verification** without breaking emergency access

#### [`lib/validation/file_validation.dart`](lib/validation/file_validation.dart)
File attachment security:
- **Local storage only** (no cloud uploads)
- **File type validation** and content verification
- **Size warnings** and integrity checking
- **Secure file copying** with unique naming

### Documentation

#### [`/docs/SECURITY.md`](/docs/SECURITY.md)
Comprehensive security architecture documentation covering:
- **Enhanced encryption standards** with PBKDF2 implementation details
- **Cross-version compatibility** and automatic fallback mechanisms
- **Performance optimization** through key caching
- Threat model and security assumptions
- Access control mechanisms
- Emergency scenarios and safeguards

#### [`/docs/PRIVACY_ARCHITECTURE.md`](/docs/PRIVACY_ARCHITECTURE.md)
Deep dive into privacy design:
- Philosophy behind the three privacy levels
- User mental models and decision frameworks
- Technical implementation of privacy controls
- Real-world usage scenarios

### Tests

#### [`test/security_tests.dart`](test/security_tests.dart)
Comprehensive test suite covering:
- **PBKDF2 vs Legacy encryption** round-trip tests
- **Cross-version compatibility** validation
- **Performance benchmarking** for key derivation
- Privacy level access control verification
- Security questions validation
- Edge cases and attack scenarios
- Integration tests for complete user flows

## The Three Privacy Levels Explained

### Basic Privacy
**"They can see this right away if something happens to me"**

- **Use Case**: Emergency contacts, basic instructions, immediate needs
- **Access**: Available immediately after security questions
- **Technical**: Base64 encoding with integrity checksums and V2 markers
- **Example**: Medical information, emergency contacts

### Sensitive Privacy
**"They can see this, but only after thinking about it"**

- **Use Case**: Personal letters, family secrets, emotional content
- **Access**: Available after configurable delay (12 hours to 10 years)
- **Technical**: Base64 encoding with timestamp-based access control and V2 format
- **Example**: "To be opened 6 months after my passing"

### Ultra Privacy
**"This is for me only, never for anyone else"**

- **Use Case**: Completely private thoughts, confidential information
- **Access**: Owner only, requires master password, never shared
- **Technical**: Full AES-256 encryption with PBKDF2-HMAC-SHA256 key derivation
- **Example**: Private diary, therapy notes

## Enhanced Security Features

### **PBKDF2-Based Encryption**
```dart
// Enhanced key derivation with 10,000 iterations
final salt = CoreEncryptionService.generateSalt();
final key = await CoreEncryptionService.deriveKeyFromPassphrasePBKDF2(
  userPassword, 
  salt, 
  iterations: 10000
);
final encrypted = await CoreEncryptionService.encryptText(content, userPassword);
```

### **No Backdoors with Enhanced Protection**
```dart
// Ultra vaults are mathematically impossible to access without the master password
if (privacyLevel == PrivacyLevel.ultra && userType == UserType.trusted) {
  return false; // Even with PBKDF2, trusted persons cannot access
}
```

### **Precise Time Controls**
```dart
// Sensitive vaults respect owner's timing choices with per-vault granularity
if (DateTime.now().isAfter(unlockTime.add(Duration(hours: delayHours)))) {
  return true; // Time has passed, access granted
}
```

### **Enhanced Cryptographic Integrity**
```dart
// Every piece of data has multiple layers of integrity verification
final checksum = sha256.convert(utf8.encode(content)).toString();
final package = {
  'version': 2,
  'salt': base64.encode(salt),
  'checksum': checksum,
  'timestamp': DateTime.now().millisecondsSinceEpoch,
};
```

### **Performance Optimization**
```dart
// Key caching reduces PBKDF2 computation overhead
static final Map<String, Key> _keyCache = {};

// Memory management with secure cleanup
static void secureCleanup(List<int> sensitiveData) {
  for (int i = 0; i < sensitiveData.length; i++) {
    sensitiveData[i] = 0;
  }
}
```

## Running the Tests

To verify the enhanced security implementation:

```bash
# Install dependencies (including cryptography package)
dart pub get

# Run all enhanced security tests
dart test test/security_tests.dart

# Run specific test groups
dart test test/security_tests.dart --name "Core Encryption Tests"
dart test test/security_tests.dart --name "PBKDF2 vs Legacy Compatibility"
dart test test/security_tests.dart --name "Privacy Levels Access Control Tests"
dart test test/security_tests.dart --name "Performance and Memory Tests"
```

## Enhanced Dependencies

The transparency repository requires these dependencies:

```yaml
dependencies:
  encrypt: ^5.0.1
  crypto: ^3.0.3
  cryptography: ^2.5.0  # For PBKDF2-HMAC-SHA256
  
dev_dependencies:
  test: ^1.21.0
```

## Security Audit Guidelines

### For Security Researchers

1. **Focus Areas**:
   - **PBKDF2 implementation** in `core_encryption.dart`
   - **Cross-version compatibility** and fallback mechanisms
   - **Key caching security** and memory management
   - Access control logic in `privacy_levels.dart`
   - Authentication in `security_questions.dart`

2. **Enhanced Test Vectors**: Use the comprehensive async test suite as a starting point

3. **Performance Analysis**: Verify PBKDF2 performance vs security trade-offs

4. **Edge Cases**: Pay special attention to version compatibility and caching behavior

5. **Threat Model**: Review against the enhanced threat model in `SECURITY.md`

### Responsible Disclosure

Found a security issue? We appreciate responsible disclosure:

1. **Do Not**: Publicly disclose before coordination
2. **Do**: Submit detailed reports via the repository issue tracker
3. **Include**: Steps to reproduce, potential impact, suggested fixes
4. **Expect**: Acknowledgment within 48 hours, fixes within reasonable timeframes

## Trust Through Enhanced Transparency

### What are we trying to prove?:

**Enhanced Cryptographic Protection**: PBKDF2-HMAC-SHA256 with 10,000 iterations  
**Salt-Based Security**: Unique salt per encryption prevents rainbow table attacks  
**Optimized Binary Format**: Enhanced storage format with version compatibility  
**Performance Optimization**: Smart caching without compromising security  
**Backward Compatibility**: Your existing data remains fully accessible  
**No Hidden Surveillance**: All data processing is visible and auditable  
**No Backdoor Access**: Mathematical impossibility of unauthorized access  
**Privacy by Design**: Technical enforcement of user privacy choices  
**Standard Cryptography**: No custom crypto, only proven algorithms (now enhanced)  
**Local-Only Processing**: Your data never leaves your device

## Enhanced Security Promises

### **Version 2.0 Security Enhancements**

1. **PBKDF2 Protection**: 10,000 iterations vs single hash for brute-force resistance
2. **Unique Salt Generation**: Every encryption uses a unique cryptographic salt
3. **Optimized Storage**: Enhanced binary format reduces overhead and improves security
4. **Smart Caching**: PBKDF2 results cached securely for performance without security loss
5. **Seamless Compatibility**: Automatic detection and fallback for existing encrypted data
6. **Enhanced Validation**: Multi-layer integrity checking and corruption detection

### **Maintained Guarantees**


1. **Your Data Stays Local**: Never uploaded to our servers
2. **You Control Access**: Granular privacy levels you configure
3. **Your Timing Rules**: Delays and access controls you set
4. **No Backdoors**: Mathematically impossible for us to access your data
5. **Full Transparency**: Security implementation is open for audit
6. **Enhanced Protection**: PBKDF2-HMAC-SHA256 with 10,000 iterations
7. **Salt-Based Security**: Unique salt prevents rainbow table attacks
8. **Optimized Performance**: Smart caching without security compromise
9. **Backward Compatibility**: Your existing data remains fully accessible
10. **Continuous Improvement**: Ongoing security enhancements you can verify

## Building Trust in Digital Legacy

Traditional digital legacy solutions ask you to **trust them with your most sensitive information**. EchoVaults takes a different approach:

### **Trust Through Technology, Not Promises**

Instead of saying *"Trust us, we'll protect your data"*, we say:  
*"Here's exactly how we protect your data - verify it yourself."*

And now with Version 2.0: *"Here's how we've made it even more secure while keeping everything you already stored perfectly safe."*

### **Privacy as a Right, Not a Privilege**

Your privacy isn't something we grant you - it's something we **mathematically guarantee** through technology you can inspect and verify. With PBKDF2, we've made that guarantee exponentially stronger.

---

## About EchoVaults

EchoVaults is built by a team that believes **privacy is a human right** and **transparency builds trust**. We're committed to proving that you can build a successful business while respecting user privacy, providing complete transparency around security, **and continuously improving protection without breaking compatibility**.

**Website**: [echovaults.org](https://echovaults.org)  
**Transparency Page**: [echovaults.org/transparency](https://echovaults.org/transparency)
**Contributors**: [echovaults.org/contributors](https://echovaults.org/contributors)

---

*"In matters of life and death, trust must be earned through transparency and continuously strengthened through verifiable technology."*

## License

This transparency repository is released under the **MIT License** to enable maximum scrutiny and verification by security researchers and the broader community.

See [LICENSE](LICENSE) for full details.

---

**Last Updated**: July 21st 2025  
**Repository Version**: 2.0.0 (Enhanced with PBKDF2)  
**Corresponds to EchoVaults App Version**: 2.1.0  
**Security Level**: Enhanced (PBKDF2-HMAC-SHA256)  
**Backward Compatibility**: Full (V1 Legacy SHA-256 supported)