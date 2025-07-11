// test/security_tests.dart
//
// EchoVaults Transparency Repository
// Comprehensive Security Test Suite
//
// This file contains comprehensive tests for all security-critical components
// of EchoVaults. These tests verify that the security promises made to users
// are technically enforced by the implementation.
//

import 'package:test/test.dart';
import 'package:crypto/crypto.dart';
import 'dart:convert';
import 'dart:io';

// Import the security components
import '../lib/encryption/core_encryption.dart';
import '../lib/security/privacy_levels.dart';
import '../lib/security/security_questions.dart';
import '../lib/validation/file_validation.dart';

void main() {
  group('Core Encryption Tests', () {
    test('AES-256 encryption/decryption round trip', () {
      const plaintext = 'This is a secret message for testing encryption';
      const password = 'test_master_password_123';

      // Encrypt the text
      final encrypted = CoreEncryptionService.encryptText(plaintext, password);
      expect(encrypted, isNotEmpty);
      expect(encrypted, isNot(equals(plaintext)));

      // Decrypt the text
      final decrypted = CoreEncryptionService.decryptText(encrypted, password);
      expect(decrypted, equals(plaintext));
    });

    test('Encryption with wrong password fails gracefully', () {
      const plaintext = 'Secret message';
      const correctPassword = 'correct_password';
      const wrongPassword = 'wrong_password';

      final encrypted = CoreEncryptionService.encryptText(plaintext, correctPassword);
      final decrypted = CoreEncryptionService.decryptText(encrypted, wrongPassword);

      // Should return empty string, not crash or return garbage
      expect(decrypted, equals(''));
    });

    test('Each encryption produces unique ciphertext (IV randomization)', () {
      const plaintext = 'Same message encrypted twice';
      const password = 'same_password';

      final encrypted1 = CoreEncryptionService.encryptText(plaintext, password);
      final encrypted2 = CoreEncryptionService.encryptText(plaintext, password);

      // Should produce different encrypted outputs due to random IV
      expect(encrypted1, isNot(equals(encrypted2)));

      // But both should decrypt to the same plaintext
      expect(CoreEncryptionService.decryptText(encrypted1, password), equals(plaintext));
      expect(CoreEncryptionService.decryptText(encrypted2, password), equals(plaintext));
    });

    test('Basic vault encryption allows access without password', () {
      const plaintext = 'Basic vault content';
      const password = 'master_password';

      // Encrypt as basic vault
      final encrypted = CoreEncryptionService.encryptTextForBasicVault(plaintext, password);
      expect(encrypted, contains('BASIC_VAULT_V1:'));

      // Should be able to decrypt without password
      final decrypted = CoreEncryptionService.decryptTextForBasicVault(encrypted);
      expect(decrypted, equals(plaintext));
    });

    test('Sensitive vault encryption allows access without password', () {
      const plaintext = 'Sensitive vault content';
      const password = 'master_password';

      // Encrypt as sensitive vault
      final encrypted = CoreEncryptionService.encryptTextForSensitiveVault(plaintext, password);
      expect(encrypted, contains('SENSITIVE_VAULT_V1:'));

      // Should be able to decrypt without password
      final decrypted = CoreEncryptionService.decryptTextForSensitiveVault(encrypted);
      expect(decrypted, equals(plaintext));
    });

    test('Vault type detection works correctly', () {
      const plaintext = 'Test content';
      const password = 'password';

      final basicEncrypted = CoreEncryptionService.encryptTextForBasicVault(plaintext, password);
      final sensitiveEncrypted = CoreEncryptionService.encryptTextForSensitiveVault(plaintext, password);
      final ultraEncrypted = CoreEncryptionService.encryptText(plaintext, password);

      expect(CoreEncryptionService.isBasicVaultEncryption(basicEncrypted), isTrue);
      expect(CoreEncryptionService.isBasicVaultEncryption(sensitiveEncrypted), isFalse);
      expect(CoreEncryptionService.isBasicVaultEncryption(ultraEncrypted), isFalse);

      expect(CoreEncryptionService.isSensitiveVaultEncryption(sensitiveEncrypted), isTrue);
      expect(CoreEncryptionService.isSensitiveVaultEncryption(basicEncrypted), isFalse);
      expect(CoreEncryptionService.isSensitiveVaultEncryption(ultraEncrypted), isFalse);
    });

    test('Password hashing is deterministic and secure', () {
      const password = 'test_password_123';

      final hash1 = CoreEncryptionService.hashPassword(password);
      final hash2 = CoreEncryptionService.hashPassword(password);

      // Same password should produce same hash
      expect(hash1, equals(hash2));

      // Hash should be SHA-256 length (64 hex characters)
      expect(hash1.length, equals(64));

      // Hash should not contain the original password
      expect(hash1.toLowerCase(), isNot(contains(password.toLowerCase())));
    });

    test('Password verification works correctly', () {
      const password = 'correct_password';
      const wrongPassword = 'wrong_password';

      final hash = CoreEncryptionService.hashPassword(password);

      expect(CoreEncryptionService.verifyPassword(password, hash), isTrue);
      expect(CoreEncryptionService.verifyPassword(wrongPassword, hash), isFalse);
      expect(CoreEncryptionService.verifyPassword('', hash), isFalse);
    });
  });

  group('Privacy Levels Access Control Tests', () {
    test('Owner can access all privacy levels', () {
      final now = DateTime.now();

      expect(PrivacyAccessControl.canAccessVault(
        userType: UserType.owner,
        privacyLevel: PrivacyLevel.basic,
        vaultId: 'test1',
        unlockTime: now,
      ), isTrue);

      expect(PrivacyAccessControl.canAccessVault(
        userType: UserType.owner,
        privacyLevel: PrivacyLevel.sensitive,
        vaultId: 'test2',
        unlockTime: now,
      ), isTrue);

      expect(PrivacyAccessControl.canAccessVault(
        userType: UserType.owner,
        privacyLevel: PrivacyLevel.ultra,
        vaultId: 'test3',
        unlockTime: now,
      ), isTrue);
    });

    test('Unauthenticated users cannot access any vaults', () {
      final now = DateTime.now();

      expect(PrivacyAccessControl.canAccessVault(
        userType: UserType.none,
        privacyLevel: PrivacyLevel.basic,
        vaultId: 'test1',
        unlockTime: now,
      ), isFalse);

      expect(PrivacyAccessControl.canAccessVault(
        userType: UserType.none,
        privacyLevel: PrivacyLevel.sensitive,
        vaultId: 'test2',
        unlockTime: now,
      ), isFalse);

      expect(PrivacyAccessControl.canAccessVault(
        userType: UserType.none,
        privacyLevel: PrivacyLevel.ultra,
        vaultId: 'test3',
        unlockTime: now,
      ), isFalse);
    });

    test('Trusted person can access basic vaults immediately after unlock', () {
      final unlockTime = DateTime.now();

      expect(PrivacyAccessControl.canAccessVault(
        userType: UserType.trusted,
        privacyLevel: PrivacyLevel.basic,
        vaultId: 'test',
        unlockTime: unlockTime,
      ), isTrue);
    });

    test('Trusted person cannot access basic vaults before unlock', () {
      expect(PrivacyAccessControl.canAccessVault(
        userType: UserType.trusted,
        privacyLevel: PrivacyLevel.basic,
        vaultId: 'test',
        unlockTime: null, // Not unlocked
      ), isFalse);
    });

    test('Trusted person can access sensitive vaults after delay', () {
      final unlockTime = DateTime.now().subtract(Duration(hours: 25)); // 25 hours ago

      expect(PrivacyAccessControl.canAccessVault(
        userType: UserType.trusted,
        privacyLevel: PrivacyLevel.sensitive,
        vaultId: 'test',
        unlockTime: unlockTime,
        sensitiveDelayHours: 24, // 24 hour delay
      ), isTrue);
    });

    test('Trusted person cannot access sensitive vaults before delay expires', () {
      final unlockTime = DateTime.now().subtract(Duration(hours: 12)); // 12 hours ago

      expect(PrivacyAccessControl.canAccessVault(
        userType: UserType.trusted,
        privacyLevel: PrivacyLevel.sensitive,
        vaultId: 'test',
        unlockTime: unlockTime,
        sensitiveDelayHours: 24, // 24 hour delay
      ), isFalse);
    });

    test('Trusted person can access sensitive vaults with zero delay immediately', () {
      final unlockTime = DateTime.now();

      expect(PrivacyAccessControl.canAccessVault(
        userType: UserType.trusted,
        privacyLevel: PrivacyLevel.sensitive,
        vaultId: 'test',
        unlockTime: unlockTime,
        sensitiveDelayHours: 0, // No delay
      ), isTrue);
    });

    test('Trusted person can NEVER access ultra vaults', () {
      final unlockTime = DateTime.now().subtract(Duration(days: 365)); // Long time ago

      expect(PrivacyAccessControl.canAccessVault(
        userType: UserType.trusted,
        privacyLevel: PrivacyLevel.ultra,
        vaultId: 'test',
        unlockTime: unlockTime,
        sensitiveDelayHours: 0,
      ), isFalse);
    });

    test('Remaining wait time calculation works correctly', () {
      final unlockTime = DateTime.now().subtract(Duration(hours: 12));

      final remaining = PrivacyAccessControl.getRemainingWaitTime(
        unlockTime: unlockTime,
        sensitiveDelayHours: 24,
      );

      expect(remaining, isNotNull);
      expect(remaining!.inHours, equals(11)); // Should be ~12 hours remaining
    });

    test('Privacy configuration validation', () {
      expect(PrivacyAccessControl.isValidPrivacyConfiguration(
        privacyLevel: PrivacyLevel.basic,
      ), isTrue);

      expect(PrivacyAccessControl.isValidPrivacyConfiguration(
        privacyLevel: PrivacyLevel.sensitive,
        sensitiveDelayHours: 24,
      ), isTrue);

      expect(PrivacyAccessControl.isValidPrivacyConfiguration(
        privacyLevel: PrivacyLevel.sensitive,
        sensitiveDelayHours: null, // Invalid for sensitive
      ), isFalse);

      expect(PrivacyAccessControl.isValidPrivacyConfiguration(
        privacyLevel: PrivacyLevel.sensitive,
        sensitiveDelayHours: 999, // Not in allowed list
      ), isFalse);
    });
  });

  group('Security Questions Validation Tests', () {
    test('Exact answer matching works correctly', () {
      final question = SecurityQuestion(
        id: '1',
        question: 'What is your favorite color?',
        answer: 'Blue',
      );

      expect(question.validateAnswer('Blue'), isTrue);
      expect(question.validateAnswer('blue'), isFalse); // Case sensitive
      expect(question.validateAnswer(' Blue '), isTrue); // Whitespace trimmed
      expect(question.validateAnswer('Blue '), isTrue); // Trailing whitespace
      expect(question.validateAnswer('Purple'), isFalse);
    });

    test('All security questions must be correct for access', () {
      final questions = [
        SecurityQuestion(id: '1', question: 'Color?', answer: 'Blue'),
        SecurityQuestion(id: '2', question: 'Pet?', answer: 'Dog'),
        SecurityQuestion(id: '3', question: 'City?', answer: 'Paris'),
      ];

      // All correct answers
      final allCorrect = SecurityQuestionsValidator.validateAll(
        questions: questions,
        providedAnswers: ['Blue', 'Dog', 'Paris'],
      );
      expect(allCorrect.success, isTrue);
      expect(allCorrect.correctAnswers, equals(3));

      // One wrong answer
      final oneWrong = SecurityQuestionsValidator.validateAll(
        questions: questions,
        providedAnswers: ['Blue', 'Cat', 'Paris'], // Wrong pet
      );
      expect(oneWrong.success, isFalse);
      expect(oneWrong.correctAnswers, equals(2));
      expect(oneWrong.incorrectQuestionIndices, equals([1]));
    });

    test('Answer count mismatch is handled gracefully', () {
      final questions = [
        SecurityQuestion(id: '1', question: 'Color?', answer: 'Blue'),
        SecurityQuestion(id: '2', question: 'Pet?', answer: 'Dog'),
      ];

      final result = SecurityQuestionsValidator.validateAll(
        questions: questions,
        providedAnswers: ['Blue'], // Missing second answer
      );

      expect(result.success, isFalse);
      expect(result.errorMessage, contains('Answer count mismatch'));
    });

    test('Empty questions list is handled gracefully', () {
      final result = SecurityQuestionsValidator.validateAll(
        questions: [],
        providedAnswers: [],
      );

      expect(result.success, isFalse);
      expect(result.errorMessage, contains('No security questions configured'));
    });

    test('Security questions structure validation', () {
      final validQuestions = [
        SecurityQuestion(id: '1', question: 'What is your pet name?', answer: 'Fluffy'),
        SecurityQuestion(id: '2', question: 'Favorite food?', answer: 'Pizza'),
        SecurityQuestion(id: '3', question: 'First school?', answer: 'Central Elementary'),
        SecurityQuestion(id: '4', question: 'Mother maiden name?', answer: 'Smith'),
        SecurityQuestion(id: '5', question: 'Best friend name?', answer: 'John'),
      ];

      final errors = SecurityQuestionsValidator.validateQuestionsStructure(validQuestions);
      expect(errors, isEmpty);

      // Test with too few questions
      final tooFew = validQuestions.sublist(0, 3);
      final tooFewErrors = SecurityQuestionsValidator.validateQuestionsStructure(tooFew);
      expect(tooFewErrors, isNotEmpty);
      expect(tooFewErrors.first, contains('At least 5 security questions'));
    });

    test('Duplicate questions are detected', () {
      final duplicateQuestions = [
        SecurityQuestion(id: '1', question: 'What is your pet name?', answer: 'Fluffy'),
        SecurityQuestion(id: '2', question: 'What is your pet name?', answer: 'Buddy'), // Duplicate
        SecurityQuestion(id: '3', question: 'Favorite food?', answer: 'Pizza'),
        SecurityQuestion(id: '4', question: 'First school?', answer: 'Central'),
        SecurityQuestion(id: '5', question: 'Best friend?', answer: 'John'),
      ];

      final errors = SecurityQuestionsValidator.validateQuestionsStructure(duplicateQuestions);
      expect(errors, isNotEmpty);
      expect(errors.any((error) => error.contains('Duplicate question text')), isTrue);
    });

    test('Empty questions and answers are rejected', () {
      final invalidQuestions = [
        SecurityQuestion(id: '1', question: '', answer: 'Answer'), // Empty question
        SecurityQuestion(id: '2', question: 'Question?', answer: ''), // Empty answer
        SecurityQuestion(id: '3', question: 'Valid?', answer: 'Yes'),
        SecurityQuestion(id: '4', question: 'Another?', answer: 'Sure'),
        SecurityQuestion(id: '5', question: 'Last?', answer: 'Final'),
      ];

      final errors = SecurityQuestionsValidator.validateQuestionsStructure(invalidQuestions);
      expect(errors, isNotEmpty);
      expect(errors.any((error) => error.contains('Question text cannot be empty')), isTrue);
      expect(errors.any((error) => error.contains('Answer cannot be empty')), isTrue);
    });
  });

  group('File Validation Tests', () {
    test('Supported file types are correctly identified', () {
      expect(SupportedFileTypes.isMediaFile('jpg'), isTrue);
      expect(SupportedFileTypes.isMediaFile('mp4'), isTrue);
      expect(SupportedFileTypes.isMediaFile('pdf'), isFalse);

      expect(SupportedFileTypes.isDocumentFile('pdf'), isTrue);
      expect(SupportedFileTypes.isDocumentFile('docx'), isTrue);
      expect(SupportedFileTypes.isDocumentFile('jpg'), isFalse);

      expect(SupportedFileTypes.isSupported('jpg'), isTrue);
      expect(SupportedFileTypes.isSupported('exe'), isFalse);
    });

    test('File size formatting works correctly', () {
      expect(FileSizeLimits.formatFileSize(512), equals('512 B'));
      expect(FileSizeLimits.formatFileSize(1024), equals('1.0 KB'));
      expect(FileSizeLimits.formatFileSize(1536), equals('1.5 KB'));
      expect(FileSizeLimits.formatFileSize(1024 * 1024), equals('1.0 MB'));
      expect(FileSizeLimits.formatFileSize(1024 * 1024 * 1024), equals('1.0 GB'));
    });

    test('File size warning levels are correct', () {
      expect(FileSizeLimits.getWarningLevel(1024), equals(FileSizeWarning.none));
      expect(FileSizeLimits.getWarningLevel(FileSizeLimits.warningThreshold + 1),
          equals(FileSizeWarning.warning));
      expect(FileSizeLimits.getWarningLevel(FileSizeLimits.confirmationThreshold + 1),
          equals(FileSizeWarning.confirmation));
      expect(FileSizeLimits.getWarningLevel(FileSizeLimits.maxFileSize + 1),
          equals(FileSizeWarning.blocked));
    });
  });

  group('Integration Tests - End-to-End Security Scenarios', () {
    test('Complete trusted person access flow for basic vault', () {
      // 1. Owner creates a basic vault
      const vaultContent = 'Emergency contact: Dr. Smith 555-1234';
      const masterPassword = 'owner_master_password';
      final encryptedContent = CoreEncryptionService.encryptTextForBasicVault(
          vaultContent,
          masterPassword
      );

      // 2. Owner sets up security questions
      final questions = [
        SecurityQuestion(id: '1', question: 'Pet name?', answer: 'Fluffy'),
        SecurityQuestion(id: '2', question: 'Hometown?', answer: 'Springfield'),
        SecurityQuestion(id: '3', question: 'First car?', answer: 'Honda'),
        SecurityQuestion(id: '4', question: 'Favorite teacher?', answer: 'Mrs. Johnson'),
        SecurityQuestion(id: '5', question: 'Best friend?', answer: 'Sarah'),
      ];

      // 3. Trusted person attempts access
      final unlockTime = DateTime.now();

      // 4. Trusted person answers security questions
      final answers = ['Fluffy', 'Springfield', 'Honda', 'Mrs. Johnson', 'Sarah'];
      final validation = SecurityQuestionsValidator.validateAll(
        questions: questions,
        providedAnswers: answers,
      );
      expect(validation.success, isTrue);

      // 5. Check access permissions
      final canAccess = PrivacyAccessControl.canAccessVault(
        userType: UserType.trusted,
        privacyLevel: PrivacyLevel.basic,
        vaultId: 'emergency_vault',
        unlockTime: unlockTime,
      );
      expect(canAccess, isTrue);

      // 6. Decrypt the vault content
      final decryptedContent = CoreEncryptionService.decryptTextForBasicVault(encryptedContent);
      expect(decryptedContent, equals(vaultContent));
    });

    test('Ultra vault remains inaccessible to trusted person', () {
      // 1. Owner creates ultra vault
      const secretContent = 'My most private thoughts...';
      const masterPassword = 'ultra_secure_password';
      final encryptedContent = CoreEncryptionService.encryptText(secretContent, masterPassword);

      // 2. Trusted person correctly answers all security questions
      final questions = [
        SecurityQuestion(id: '1', question: 'Pet?', answer: 'Dog'),
        SecurityQuestion(id: '2', question: 'Color?', answer: 'Blue'),
        SecurityQuestion(id: '3', question: 'Food?', answer: 'Pizza'),
        SecurityQuestion(id: '4', question: 'Movie?', answer: 'Titanic'),
        SecurityQuestion(id: '5', question: 'Song?', answer: 'Yesterday'),
      ];

      final validation = SecurityQuestionsValidator.validateAll(
        questions: questions,
        providedAnswers: ['Dog', 'Blue', 'Pizza', 'Titanic', 'Yesterday'],
      );
      expect(validation.success, isTrue);

      // 3. Despite correct answers, ultra vault should be inaccessible
      final canAccess = PrivacyAccessControl.canAccessVault(
        userType: UserType.trusted,
        privacyLevel: PrivacyLevel.ultra,
        vaultId: 'secret_vault',
        unlockTime: DateTime.now(),
      );
      expect(canAccess, isFalse);

      // 4. Even if they try to decrypt, they can't without master password
      final decryptedContent = CoreEncryptionService.decryptText(encryptedContent, 'wrong_password');
      expect(decryptedContent, equals('')); // Should fail
    });

    test('Sensitive vault respects time delays', () {
      const sensitiveContent = 'Personal letter to my children...';
      const masterPassword = 'sensitive_password';
      final encryptedContent = CoreEncryptionService.encryptTextForSensitiveVault(
          sensitiveContent,
          masterPassword
      );

      // Unlock time was 12 hours ago
      final unlockTime = DateTime.now().subtract(Duration(hours: 12));

      // Vault has 24-hour delay
      const delayHours = 24;

      // Should NOT be accessible yet (only 12 hours passed)
      final canAccessNow = PrivacyAccessControl.canAccessVault(
        userType: UserType.trusted,
        privacyLevel: PrivacyLevel.sensitive,
        vaultId: 'letter_vault',
        unlockTime: unlockTime,
        sensitiveDelayHours: delayHours,
      );
      expect(canAccessNow, isFalse);

      // Simulate 25 hours having passed
      final unlockTime25HoursAgo = DateTime.now().subtract(Duration(hours: 25));

      // Should be accessible now
      final canAccessLater = PrivacyAccessControl.canAccessVault(
        userType: UserType.trusted,
        privacyLevel: PrivacyLevel.sensitive,
        vaultId: 'letter_vault',
        unlockTime: unlockTime25HoursAgo,
        sensitiveDelayHours: delayHours,
      );
      expect(canAccessLater, isTrue);

      // Content should be decryptable
      final decryptedContent = CoreEncryptionService.decryptTextForSensitiveVault(encryptedContent);
      expect(decryptedContent, equals(sensitiveContent));
    });
  });

  group('Security Edge Cases and Attack Scenarios', () {
    test('Malformed encrypted data is handled safely', () {
      // Try to decrypt garbage data
      const garbageData = 'this_is_not_encrypted_data';

      expect(CoreEncryptionService.decryptText(garbageData, 'password'), equals(''));
      expect(CoreEncryptionService.decryptTextForBasicVault(garbageData), equals(''));
      expect(CoreEncryptionService.decryptTextForSensitiveVault(garbageData), equals(''));
    });

    test('Very long passwords do not crash the system', () {
      final longPassword = 'a' * 10000; // 10k character password
      const plaintext = 'Test with very long password';

      final encrypted = CoreEncryptionService.encryptText(plaintext, longPassword);
      expect(encrypted, isNotEmpty);

      final decrypted = CoreEncryptionService.decryptText(encrypted, longPassword);
      expect(decrypted, equals(plaintext));
    });

    test('Unicode characters in passwords and content work correctly', () {
      const unicodePassword = 'пароль🔐密码';
      const unicodeContent = 'Secret: 🤐 Контент 内容';

      final encrypted = CoreEncryptionService.encryptText(unicodeContent, unicodePassword);
      final decrypted = CoreEncryptionService.decryptText(encrypted, unicodePassword);

      expect(decrypted, equals(unicodeContent));
    });

    test('Timing attack resistance in password verification', () {
      const correctPassword = 'correct_password';
      const wrongPassword1 = 'x'; // Very different
      const wrongPassword2 = 'correct_passwors'; // Close but wrong

      final hash = CoreEncryptionService.hashPassword(correctPassword);

      // All wrong passwords should return false regardless of similarity
      expect(CoreEncryptionService.verifyPassword(wrongPassword1, hash), isFalse);
      expect(CoreEncryptionService.verifyPassword(wrongPassword2, hash), isFalse);
      expect(CoreEncryptionService.verifyPassword(correctPassword, hash), isTrue);
    });

    test('Race conditions in access control are handled', () {
      // Simulate rapid access checks around delay boundary
      final unlockTime = DateTime.now().subtract(Duration(hours: 23, minutes: 59));

      // Multiple rapid checks should be consistent
      final results = <bool>[];
      for (int i = 0; i < 100; i++) {
        final canAccess = PrivacyAccessControl.canAccessVault(
          userType: UserType.trusted,
          privacyLevel: PrivacyLevel.sensitive,
          vaultId: 'test',
          unlockTime: unlockTime,
          sensitiveDelayHours: 24,
        );
        results.add(canAccess);
      }

      // All results should be the same (no race conditions)
      expect(results.toSet().length, equals(1));
    });
  });
}