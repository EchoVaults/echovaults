// lib/security/security_questions.dart
//
// EchoVaults Transparency Repository
// Security Questions Validation Logic
//
// This file contains the complete implementation of how security questions
// are validated when trusted persons attempt to access vaults.
//
// Key Security Principles:
// - Exact match validation (case-sensitive, character-sensitive)
// - No fuzzy matching or autocorrect to prevent unauthorized access
// - All questions must be answered correctly
// - Failed attempts are logged but not rate-limited (to prevent lockouts in emergencies)
//

import 'package:flutter/foundation.dart';

/// Represents a single security question with its answer
class SecurityQuestion {
  /// Unique identifier for this question
  final String id;

  /// The question text as entered by the vault owner
  final String question;

  /// The correct answer as entered by the vault owner
  /// Note: This is stored exactly as entered - case sensitive, whitespace preserved
  final String answer;

  const SecurityQuestion({
    required this.id,
    required this.question,
    required this.answer,
  });

  /// Creates a SecurityQuestion from a map (for JSON serialization)
  factory SecurityQuestion.fromMap(Map<String, dynamic> map) {
    return SecurityQuestion(
      id: map['id'] ?? '',
      question: map['question'] ?? '',
      answer: map['answer'] ?? '',
    );
  }

  /// Converts this SecurityQuestion to a map (for JSON serialization)
  Map<String, dynamic> toMap() {
    return {
      'id': id,
      'question': question,
      'answer': answer,
    };
  }

  /// Validates a provided answer against the correct answer
  ///
  /// This validation is intentionally strict:
  /// - Case sensitive: "John" != "john"
  /// - Whitespace sensitive: "John Smith" != "John  Smith"
  /// - No auto-correction or fuzzy matching
  ///
  /// This strictness is by design to prevent unauthorized access while
  /// ensuring that people who truly know the vault owner can answer correctly.
  ///
  /// [providedAnswer] Answer provided by the person attempting access
  ///
  /// Returns: true if answer is exactly correct, false otherwise
  bool validateAnswer(String providedAnswer) {
    // Remove leading/trailing whitespace from provided answer only
    // (correct answer is stored exactly as entered by owner)
    final trimmedProvided = providedAnswer.trim();
    final trimmedCorrect = answer.trim();

    // Exact string comparison - case and character sensitive
    return trimmedProvided == trimmedCorrect;
  }

  @override
  String toString() => 'SecurityQuestion(id: $id, question: $question)';

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    return other is SecurityQuestion &&
        other.id == id &&
        other.question == question &&
        other.answer == answer;
  }

  @override
  int get hashCode => Object.hash(id, question, answer);
}

/// Result of a security questions validation attempt
class ValidationResult {
  /// Whether all questions were answered correctly
  final bool success;

  /// Total number of questions that were asked
  final int totalQuestions;

  /// Number of questions answered correctly
  final int correctAnswers;

  /// List of question indices that were answered incorrectly (0-based)
  final List<int> incorrectQuestionIndices;

  /// Timestamp of when validation was attempted
  final DateTime timestamp;

  /// Optional error message if validation failed due to system error
  final String? errorMessage;

  const ValidationResult({
    required this.success,
    required this.totalQuestions,
    required this.correctAnswers,
    required this.incorrectQuestionIndices,
    required this.timestamp,
    this.errorMessage,
  });

  /// Creates a successful validation result
  factory ValidationResult.success(int totalQuestions) {
    return ValidationResult(
      success: true,
      totalQuestions: totalQuestions,
      correctAnswers: totalQuestions,
      incorrectQuestionIndices: [],
      timestamp: DateTime.now(),
    );
  }

  /// Creates a failed validation result
  factory ValidationResult.failure({
    required int totalQuestions,
    required int correctAnswers,
    required List<int> incorrectQuestionIndices,
    String? errorMessage,
  }) {
    return ValidationResult(
      success: false,
      totalQuestions: totalQuestions,
      correctAnswers: correctAnswers,
      incorrectQuestionIndices: incorrectQuestionIndices,
      timestamp: DateTime.now(),
      errorMessage: errorMessage,
    );
  }

  /// Creates an error validation result
  factory ValidationResult.error(String errorMessage) {
    return ValidationResult(
      success: false,
      totalQuestions: 0,
      correctAnswers: 0,
      incorrectQuestionIndices: [],
      timestamp: DateTime.now(),
      errorMessage: errorMessage,
    );
  }

  /// Gets a human-readable description of the validation result
  String get description {
    if (errorMessage != null) {
      return 'Validation error: $errorMessage';
    }

    if (success) {
      return 'All $totalQuestions security questions answered correctly';
    }

    final incorrectCount = incorrectQuestionIndices.length;
    return '$correctAnswers of $totalQuestions questions correct ($incorrectCount incorrect)';
  }

  @override
  String toString() => 'ValidationResult(success: $success, $description)';
}

/// Core security questions validation service
///
/// This service implements the validation logic that determines whether
/// a trusted person can access vault contents. The validation is strict
/// and secure by design.
class SecurityQuestionsValidator {

  /// Validates all security questions against provided answers
  ///
  /// This is the main entry point for security validation. All questions
  /// must be answered correctly for access to be granted.
  ///
  /// Design principles:
  /// - All questions must be correct (no partial success)
  /// - Validation is case and character sensitive
  /// - No hints or error correction provided
  /// - Failed attempts are logged but don't trigger lockouts
  ///
  /// [questions] List of security questions to validate
  /// [providedAnswers] List of answers provided by the person attempting access
  ///
  /// Returns: ValidationResult with details of the validation attempt
  static ValidationResult validateAll({
    required List<SecurityQuestion> questions,
    required List<String> providedAnswers,
  }) {
    try {
      // Validate input parameters
      if (questions.isEmpty) {
        return ValidationResult.error('No security questions configured');
      }

      if (providedAnswers.length != questions.length) {
        return ValidationResult.error(
          'Answer count mismatch: expected ${questions.length}, got ${providedAnswers.length}'
        );
      }

      // Validate each question/answer pair
      int correctCount = 0;
      List<int> incorrectIndices = [];

      for (int i = 0; i < questions.length; i++) {
        final question = questions[i];
        final providedAnswer = providedAnswers[i];

        if (question.validateAnswer(providedAnswer)) {
          correctCount++;
        } else {
          incorrectIndices.add(i);

          // Log incorrect answer attempt (without revealing correct answer)
          debugPrint('Security question ${i + 1} answered incorrectly');
        }
      }

      // Determine overall success
      final allCorrect = correctCount == questions.length;

      if (allCorrect) {
        debugPrint('All ${questions.length} security questions answered correctly');
        return ValidationResult.success(questions.length);
      } else {
        debugPrint('Security validation failed: $correctCount/${questions.length} correct');
        return ValidationResult.failure(
          totalQuestions: questions.length,
          correctAnswers: correctCount,
          incorrectQuestionIndices: incorrectIndices,
        );
      }

    } catch (e) {
      debugPrint('Error during security questions validation: $e');
      return ValidationResult.error('Validation system error: $e');
    }
  }

  /// Validates answers for a subset of security questions
  ///
  /// This can be used for progressive validation or when only certain
  /// questions need to be checked.
  ///
  /// [questions] All available security questions
  /// [questionIndices] Indices of questions to validate (0-based)
  /// [providedAnswers] Answers for the selected questions
  ///
  /// Returns: ValidationResult for the subset validation
  static ValidationResult validateSubset({
    required List<SecurityQuestion> questions,
    required List<int> questionIndices,
    required List<String> providedAnswers,
  }) {
    try {
      // Validate input parameters
      if (questionIndices.length != providedAnswers.length) {
        return ValidationResult.error('Index count and answer count mismatch');
      }

      // Extract subset of questions
      List<SecurityQuestion> selectedQuestions = [];
      for (int index in questionIndices) {
        if (index < 0 || index >= questions.length) {
          return ValidationResult.error('Question index $index out of range');
        }
        selectedQuestions.add(questions[index]);
      }

      // Validate the subset
      return validateAll(
        questions: selectedQuestions,
        providedAnswers: providedAnswers,
      );

    } catch (e) {
      debugPrint('Error during subset validation: $e');
      return ValidationResult.error('Subset validation error: $e');
    }
  }

  /// Validates a single security question
  ///
  /// [question] The security question to validate
  /// [providedAnswer] The answer provided by the user
  ///
  /// Returns: true if answer is correct, false otherwise
  static bool validateSingle({
    required SecurityQuestion question,
    required String providedAnswer,
  }) {
    try {
      return question.validateAnswer(providedAnswer);
    } catch (e) {
      debugPrint('Error validating single question: $e');
      return false;
    }
  }

  /// Validates the structure and content of security questions
  ///
  /// This ensures that security questions are properly formatted and
  /// contain valid data before they are stored or used for validation.
  ///
  /// [questions] List of security questions to validate
  ///
  /// Returns: List of validation errors (empty if all valid)
  static List<String> validateQuestionsStructure(List<SecurityQuestion> questions) {
    List<String> errors = [];

    // Check minimum number of questions
    if (questions.length < 5) {
      errors.add('At least 5 security questions are required');
    }

    // Check maximum number of questions (reasonable limit)
    if (questions.length > 20) {
      errors.add('Maximum 20 security questions allowed');
    }

    // Validate each question
    for (int i = 0; i < questions.length; i++) {
      final question = questions[i];
      final questionNum = i + 1;

      // Check question ID
      if (question.id.isEmpty) {
        errors.add('Question $questionNum: ID cannot be empty');
      }

      // Check question text
      if (question.question.trim().isEmpty) {
        errors.add('Question $questionNum: Question text cannot be empty');
      }

      if (question.question.length > 500) {
        errors.add('Question $questionNum: Question text too long (max 500 characters)');
      }

      // Check answer
      if (question.answer.trim().isEmpty) {
        errors.add('Question $questionNum: Answer cannot be empty');
      }

      if (question.answer.length > 200) {
        errors.add('Question $questionNum: Answer too long (max 200 characters)');
      }

      // Check for duplicate question text
      for (int j = i + 1; j < questions.length; j++) {
        if (questions[j].question.trim().toLowerCase() ==
            question.question.trim().toLowerCase()) {
          errors.add('Questions $questionNum and ${j + 1}: Duplicate question text');
        }
      }

      // Check for duplicate IDs
      for (int j = i + 1; j < questions.length; j++) {
        if (questions[j].id == question.id) {
          errors.add('Questions $questionNum and ${j + 1}: Duplicate question ID');
        }
      }
    }

    return errors;
  }

  /// Generates a randomized order for presenting security questions
  ///
  /// This can be used to present questions in a different order each time
  /// to prevent pattern memorization by unauthorized persons.
  ///
  /// [questionCount] Number of questions available
  /// [seed] Optional seed for reproducible randomization
  ///
  /// Returns: List of question indices in randomized order
  static List<int> getRandomizedQuestionOrder(int questionCount, {int? seed}) {
    final indices = List.generate(questionCount, (index) => index);

    // Use provided seed or current timestamp for randomization
    final random = seed != null ?
        _SeededRandom(seed) :
        _SeededRandom(DateTime.now().millisecondsSinceEpoch);

    // Fisher-Yates shuffle algorithm
    for (int i = indices.length - 1; i > 0; i--) {
      final j = random.nextInt(i + 1);
      final temp = indices[i];
      indices[i] = indices[j];
      indices[j] = temp;
    }

    return indices;
  }
}

/// Simple seeded random number generator for reproducible shuffling
class _SeededRandom {
  int _seed;

  _SeededRandom(this._seed);

  int nextInt(int max) {
    _seed = (_seed * 1103515245 + 12345) & 0x7fffffff;
    return _seed % max;
  }
}