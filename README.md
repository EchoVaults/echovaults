# EchoVaults Transparency Repository

> **"Your last word should be heard only when it truly matters, and by those who truly matter."**

## What is EchoVaults?

EchoVaults is a digital legacy application that allows you to securely store messages, documents, and media for your loved ones to access after you're gone. Unlike a traditional will or note, EchoVaults gives you **granular control** over who can see what, and when.

This repository contains the **complete security and privacy implementation** of EchoVaults, made open source to build trust through transparency.

## Why Open Source the Security Layer?

When dealing with life-and-death matters, **trust cannot be built on promises alone**. It must be built on **verifiable technology**.

### What You Can Verify:
- **Encryption Implementation**: See exactly how your data is protected
- **Privacy Controls**: Verify how the three privacy levels work
- **Access Logic**: Understand who can see what, and when
- **No Backdoors**: Confirm there are no hidden access methods
- **Local-Only Storage**: Verify data never leaves your device

### What We Keep Proprietary:
- **User Interface**: Our design and user experience
- **Trademarked Name**: EchoVaults as brand

## Repository Contents

### Core Security Components

#### [`lib/encryption/core_encryption.dart`](lib/encryption/core_encryption.dart)
The heart of EchoVaults security. Contains:
- **AES-256 encryption** implementation
- **Key derivation** from user passwords
- **Privacy-level specific encryption** (Basic, Sensitive, Ultra)
- **Password hashing and verification**

```dart
// Example: Ultra vault encryption (owner-only)
final encrypted = CoreEncryptionService.encryptText(content, masterPassword);

// Example: Basic vault encoding (accessible to trusted persons)
final encoded = CoreEncryptionService.encryptTextForBasicVault(content, masterPassword);
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

#### [`SECURITY.md`](SECURITY.md)
Comprehensive security architecture documentation covering:
- Encryption standards and implementation
- Threat model and security assumptions
- Access control mechanisms
- Emergency scenarios and safeguards

#### [`PRIVACY_ARCHITECTURE.md`](PRIVACY_ARCHITECTURE.md)
Deep dive into privacy design:
- Philosophy behind the three privacy levels
- User mental models and decision frameworks
- Technical implementation of privacy controls
- Real-world usage scenarios

### Tests

#### [`test/security_tests.dart`](test/security_tests.dart)
Comprehensive test suite covering:
- Encryption/decryption round-trip tests
- Privacy level access control verification
- Security questions validation
- Edge cases and attack scenarios
- Integration tests for complete user flows

## The Three Privacy Levels Explained

### Basic Privacy
**"They can see this right away if something happens to me"**

- **Use Case**: Emergency contacts, basic instructions, immediate needs
- **Access**: Available immediately after security questions
- **Technical**: Base64 encoding with integrity checksums
- **Example**: Medical information, emergency contacts

### Sensitive Privacy
**"They can see this, but only after thinking about it"**

- **Use Case**: Personal letters, family secrets, emotional content
- **Access**: Available after configurable delay (12 hours to 10 years)
- **Technical**: Base64 encoding with timestamp-based access control
- **Example**: "To be opened 6 months after my passing"

### Ultra Privacy
**"This is for me only, never for anyone else"**

- **Use Case**: Completely private thoughts, confidential information
- **Access**: Owner only, requires master password, never shared
- **Technical**: Full AES-256 encryption
- **Example**: Private diary, therapy notes

## Key Security Features

### **Local-Only Encryption**
```dart
// All encryption happens on your device
final key = deriveKeyFromPassphrase(userPassword);
final encrypted = AES.encrypt(content, key);
// No cloud servers involved
```

### **No Backdoors**
```dart
// Ultra vaults are truly private
if (privacyLevel == PrivacyLevel.ultra && userType == UserType.trusted) {
  return false; // Mathematically impossible to access
}
```

### **Precise Time Controls**
```dart
// Sensitive vaults respect owner's timing choices
if (DateTime.now().isAfter(unlockTime.add(Duration(hours: delayHours)))) {
  return true; // Time has passed, access granted
}
```

### **Cryptographic Integrity**
```dart
// Every piece of data has integrity verification
final checksum = sha256.convert(utf8.encode(content)).toString();
if (storedChecksum != calculatedChecksum) {
  throw IntegrityException('Data may be corrupted');
}
```

## Running the Tests

To verify the security implementation:

```bash
# Install dependencies
dart pub get

# Run all security tests
dart test test/security_tests.dart

# Run specific test groups
dart test test/security_tests.dart --name "Core Encryption Tests"
dart test test/security_tests.dart --name "Privacy Levels Access Control Tests"
dart test test/security_tests.dart --name "Security Questions Validation Tests"
```

## Security Audit Guidelines

### For Security Researchers

1. **Focus Areas**:
   - Encryption implementation in `core_encryption.dart`
   - Access control logic in `privacy_levels.dart`
   - Authentication in `security_questions.dart`

2. **Test Vectors**: Use the comprehensive test suite as a starting point

3. **Edge Cases**: Pay special attention to boundary conditions around time delays and authentication states

4. **Threat Model**: Review against the documented threat model in `SECURITY.md`

### Responsible Disclosure

Found a security issue? We appreciate responsible disclosure:

1. **Do Not**: Publicly disclose before coordination
2. **Do**: Submit detailed reports via the repository issue tracker
3. **Include**: Steps to reproduce, potential impact, suggested fixes
4. **Expect**: Acknowledgment within 48 hours, fixes within reasonable timeframes

## Trust Through Transparency

### What This Repository Proves:

**No Hidden Surveillance**: All data processing is visible and auditable  
**No Backdoor Access**: Mathematical impossibility of unauthorized access  
**Privacy by Design**: Technical enforcement of user privacy choices  
**Standard Cryptography**: No custom crypto, only proven algorithms  
**Local-Only Processing**: Your data never leaves your device


## Building Trust in Digital Legacy

Traditional digital legacy solutions ask you to **trust them with your most sensitive information**. EchoVaults takes a different approach:

### **Trust Through Technology, Not Promises**

Instead of saying *"Trust us, we'll protect your data"*, we say:  
*"Here's exactly how we protect your data - verify it yourself."*

### **Privacy as a Right, Not a Privilege**

Your privacy isn't something we grant you - it's something we **mathematically guarantee** through technology you can inspect and verify.

### **Transparency Without Compromise**

We've open-sourced everything that matters for security while keeping the business differentiation that allows us to continue developing and improving the service.

## The EchoVaults Promise

1. **Your Data Stays Local**: Never uploaded to our servers
2. **You Control Access**: Granular privacy levels you configure
3. **Your Timing Rules**: Delays and access controls you set
4. **No Backdoors**: Mathematically impossible for us to access your data
5. **Full Transparency**: Security implementation is open for audit

---

## About EchoVaults

EchoVaults is built by a team that believes **privacy is a human right** and **transparency builds trust**. We're committed to proving that you can build a successful business while respecting user privacy and providing complete transparency around security.

**Website**: [echovaults.org](https://echovaults.org)  
**Transparency Page**: [echovaults.org/transparency](https://echovaults.org/transparency)

---

*"In matters of life and death, trust must be earned through transparency, not promised through marketing."*

## License

This transparency repository is released under the **MIT License** to enable maximum scrutiny and verification by security researchers and the broader community.

See [LICENSE](LICENSE) for full details.

---

**Last Updated**: January 2025  
**Repository Version**: 1.0.0  
**Corresponds to EchoVaults App Version**: 1.1.0
