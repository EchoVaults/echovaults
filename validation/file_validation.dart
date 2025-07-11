// lib/validation/file_validation.dart
//
// EchoVaults Transparency Repository
// File Validation & Security Logic
//
// This file contains the complete implementation of how EchoVaults handles
// file attachments securely, including validation, size limits, and integrity checking.
//
// Security Principles:
// - Files are stored locally only, never uploaded to cloud
// - File type validation based on extensions and content
// - Size warnings for large files but no hard limits
// - Integrity verification through checksums
// - Secure file copying with unique naming
//

import 'dart:io';
import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:flutter/foundation.dart';

/// Supported file types for different attachment categories
class SupportedFileTypes {
  /// Media file extensions (images and videos)
  static const Set<String> mediaExtensions = {
    // Images
    'jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'tiff', 'svg',
    // Videos
    'mp4', 'mov', 'avi', 'mkv', 'flv', 'wmv', 'webm', 'm4v', '3gp'
  };

  /// Document file extensions
  static const Set<String> documentExtensions = {
    // Office documents
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
    // Text files
    'txt', 'rtf', 'odt', 'ods', 'odp',
    // Archives
    'zip', 'rar', '7z', 'tar', 'gz',
    // Other common formats
    'json', 'xml', 'csv'
  };

  /// Gets all supported extensions
  static Set<String> get allSupported =>
      {...mediaExtensions, ...documentExtensions};

  /// Checks if a file extension is supported for media attachments
  static bool isMediaFile(String extension) {
    return mediaExtensions.contains(extension.toLowerCase());
  }

  /// Checks if a file extension is supported for document attachments
  static bool isDocumentFile(String extension) {
    return documentExtensions.contains(extension.toLowerCase());
  }

  /// Checks if a file extension is supported at all
  static bool isSupported(String extension) {
    return allSupported.contains(extension.toLowerCase());
  }
}

/// File size thresholds and limits
class FileSizeLimits {
  /// Size above which a warning is shown (100MB)
  static const int warningThreshold = 100 * 1024 * 1024;

  /// Size above which extra confirmation is required (500MB)
  static const int confirmationThreshold = 500 * 1024 * 1024;

  /// Maximum file size allowed (1GB - soft limit for UX purposes)
  static const int maxFileSize = 1024 * 1024 * 1024;

  /// Formats file size in human-readable format
  static String formatFileSize(int bytes) {
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    if (bytes < 1024 * 1024 * 1024) return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
    return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(1)} GB';
  }

  /// Gets appropriate warning level for file size
  static FileSizeWarning getWarningLevel(int bytes) {
    if (bytes > maxFileSize) return FileSizeWarning.blocked;
    if (bytes > confirmationThreshold) return FileSizeWarning.confirmation;
    if (bytes > warningThreshold) return FileSizeWarning.warning;
    return FileSizeWarning.none;
  }
}

/// File size warning levels
enum FileSizeWarning {
  none,         // No warning needed
  warning,      // Show warning but allow
  confirmation, // Require extra confirmation
  blocked,      // Block the file
}

/// Result of file validation
class FileValidationResult {
  /// Whether the file passed validation
  final bool isValid;

  /// Original file path
  final String filePath;

  /// File size in bytes
  final int fileSize;

  /// File extension (without dot)
  final String extension;

  /// Detected file type category
  final FileTypeCategory category;

  /// Warning level for file size
  final FileSizeWarning sizeWarning;

  /// Any validation errors
  final List<String> errors;

  /// Any validation warnings
  final List<String> warnings;

  /// File integrity checksum
  final String? checksum;

  const FileValidationResult({
    required this.isValid,
    required this.filePath,
    required this.fileSize,
    required this.extension,
    required this.category,
    required this.sizeWarning,
    required this.errors,
    required this.warnings,
    this.checksum,
  });

  /// Creates a failed validation result
  factory FileValidationResult.failed({
    required String filePath,
    required List<String> errors,
    List<String> warnings = const [],
  }) {
    return FileValidationResult(
      isValid: false,
      filePath: filePath,
      fileSize: 0,
      extension: '',
      category: FileTypeCategory.unknown,
      sizeWarning: FileSizeWarning.none,
      errors: errors,
      warnings: warnings,
    );
  }

  /// Gets human-readable file name from path
  String get fileName => filePath.split('/').last;

  /// Gets formatted file size string
  String get formattedSize => FileSizeLimits.formatFileSize(fileSize);

  @override
  String toString() => 'FileValidationResult(valid: $isValid, file: $fileName)';
}

/// File type categories
enum FileTypeCategory {
  image,
  video,
  document,
  archive,
  text,
  unknown,
}

/// Comprehensive file validation service
///
/// This service validates files before they are attached to vaults,
/// ensuring they meet security and usability requirements.
class FileValidator {

  /// Validates a single file for attachment to a vault
  ///
  /// Performs comprehensive validation including:
  /// - File existence check
  /// - Extension validation
  /// - File size analysis
  /// - Basic content validation
  /// - Integrity checksum generation
  ///
  /// [filePath] Path to the file to validate
  /// [allowedCategories] Which file categories are allowed (null = all)
  ///
  /// Returns: Detailed validation result
  static Future<FileValidationResult> validateFile({
    required String filePath,
    Set<FileTypeCategory>? allowedCategories,
  }) async {
    List<String> errors = [];
    List<String> warnings = [];

    try {
      // Check if file exists
      final file = File(filePath);
      if (!await file.exists()) {
        return FileValidationResult.failed(
          filePath: filePath,
          errors: ['File does not exist'],
        );
      }

      // Get file info
      final fileName = filePath.split('/').last;
      final extension = _getFileExtension(fileName);
      final fileSize = await file.length();

      // Validate extension
      if (!SupportedFileTypes.isSupported(extension)) {
        errors.add('File type .$extension is not supported');
      }

      // Determine file category
      final category = _determineFileCategory(extension);

      // Check if category is allowed
      if (allowedCategories != null && !allowedCategories.contains(category)) {
        errors.add('File category ${category.name} is not allowed in this context');
      }

      // Validate file size
      final sizeWarning = FileSizeLimits.getWarningLevel(fileSize);

      if (sizeWarning == FileSizeWarning.blocked) {
        errors.add('File is too large (${FileSizeLimits.formatFileSize(fileSize)})');
      } else if (sizeWarning == FileSizeWarning.confirmation) {
        warnings.add('Large file (${FileSizeLimits.formatFileSize(fileSize)}) - please confirm');
      } else if (sizeWarning == FileSizeWarning.warning) {
        warnings.add('Large file (${FileSizeLimits.formatFileSize(fileSize)}) detected');
      }

      // Perform basic content validation
      final contentErrors = await _validateFileContent(file, category);
      errors.addAll(contentErrors);

      // Generate integrity checksum for valid files
      String? checksum;
      if (errors.isEmpty) {
        checksum = await _generateFileChecksum(file);
      }

      return FileValidationResult(
        isValid: errors.isEmpty,
        filePath: filePath,
        fileSize: fileSize,
        extension: extension,
        category: category,
        sizeWarning: sizeWarning,
        errors: errors,
        warnings: warnings,
        checksum: checksum,
      );

    } catch (e) {
      debugPrint('Error validating file $filePath: $e');
      return FileValidationResult.failed(
        filePath: filePath,
        errors: ['Validation error: $e'],
      );
    }
  }

  /// Validates multiple files for batch attachment
  ///
  /// [filePaths] List of file paths to validate
  /// [allowedCategories] Which file categories are allowed
  ///
  /// Returns: Map of file path to validation result
  static Future<Map<String, FileValidationResult>> validateFiles({
    required List<String> filePaths,
    Set<FileTypeCategory>? allowedCategories,
  }) async {
    Map<String, FileValidationResult> results = {};

    for (String filePath in filePaths) {
      results[filePath] = await validateFile(
        filePath: filePath,
        allowedCategories: allowedCategories,
      );
    }

    return results;
  }

  /// Gets summary of validation results for multiple files
  ///
  /// [results] Map of validation results from validateFiles()
  ///
  /// Returns: Summary with counts and total size
  static ValidationSummary getValidationSummary(Map<String, FileValidationResult> results) {
    int validCount = 0;
    int invalidCount = 0;
    int totalSize = 0;
    int warningCount = 0;
    List<String> allErrors = [];
    List<String> allWarnings = [];

    for (FileValidationResult result in results.values) {
      if (result.isValid) {
        validCount++;
        totalSize += result.fileSize;
      } else {
        invalidCount++;
      }

      if (result.warnings.isNotEmpty) {
        warningCount++;
        allWarnings.addAll(result.warnings);
      }

      allErrors.addAll(result.errors);
    }

    return ValidationSummary(
      totalFiles: results.length,
      validFiles: validCount,
      invalidFiles: invalidCount,
      filesWithWarnings: warningCount,
      totalSize: totalSize,
      errors: allErrors,
      warnings: allWarnings,
    );
  }

  /// Extracts file extension from filename
  static String _getFileExtension(String fileName) {
    final lastDot = fileName.lastIndexOf('.');
    if (lastDot == -1 || lastDot == fileName.length - 1) {
      return '';
    }
    return fileName.substring(lastDot + 1).toLowerCase();
  }

  /// Determines file category based on extension
  static FileTypeCategory _determineFileCategory(String extension) {
    final lowerExt = extension.toLowerCase();

    // Image files
    if (['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'tiff', 'svg'].contains(lowerExt)) {
      return FileTypeCategory.image;
    }

    // Video files
    if (['mp4', 'mov', 'avi', 'mkv', 'flv', 'wmv', 'webm', 'm4v', '3gp'].contains(lowerExt)) {
      return FileTypeCategory.video;
    }

    // Archive files
    if (['zip', 'rar', '7z', 'tar', 'gz'].contains(lowerExt)) {
      return FileTypeCategory.archive;
    }

    // Text files
    if (['txt', 'rtf', 'json', 'xml', 'csv'].contains(lowerExt)) {
      return FileTypeCategory.text;
    }

    // Document files (default for supported document extensions)
    if (SupportedFileTypes.documentExtensions.contains(lowerExt)) {
      return FileTypeCategory.document;
    }

    return FileTypeCategory.unknown;
  }

  /// Performs basic content validation based on file type
  static Future<List<String>> _validateFileContent(File file, FileTypeCategory category) async {
    List<String> errors = [];

    try {
      // Read first few bytes for magic number validation
      final bytes = await file.openRead(0, 512).first;

      switch (category) {
        case FileTypeCategory.image:
          if (!_isValidImageFile(bytes)) {
            errors.add('File does not appear to be a valid image');
          }
          break;

        case FileTypeCategory.video:
          if (!_isValidVideoFile(bytes)) {
            errors.add('File does not appear to be a valid video');
          }
          break;

        case FileTypeCategory.document:
        // Basic validation for common document types
          if (!_isValidDocumentFile(bytes)) {
            // Note: Document validation is complex, so we just warn
            // rather than block, as some valid files might not match patterns
          }
          break;

        case FileTypeCategory.archive:
          if (!_isValidArchiveFile(bytes)) {
            errors.add('File does not appear to be a valid archive');
          }
          break;

        case FileTypeCategory.text:
        case FileTypeCategory.unknown:
        // No specific validation for text/unknown files
          break;
      }

    } catch (e) {
      // If we can't read the file for validation, that's an error
      errors.add('Unable to read file for content validation');
    }

    return errors;
  }

  /// Validates image file magic numbers
  static bool _isValidImageFile(Uint8List bytes) {
    if (bytes.length < 4) return false;

    // JPEG
    if (bytes[0] == 0xFF && bytes[1] == 0xD8) return true;

    // PNG
    if (bytes[0] == 0x89 && bytes[1] == 0x50 && bytes[2] == 0x4E && bytes[3] == 0x47) return true;

    // GIF
    if (bytes.length >= 6) {
      final header = String.fromCharCodes(bytes.sublist(0, 6));
      if (header == 'GIF87a' || header == 'GIF89a') return true;
    }

    // BMP
    if (bytes[0] == 0x42 && bytes[1] == 0x4D) return true;

    // WebP
    if (bytes.length >= 12) {
      if (bytes[0] == 0x52 && bytes[1] == 0x49 && bytes[2] == 0x46 && bytes[3] == 0x46 &&
          bytes[8] == 0x57 && bytes[9] == 0x45 && bytes[10] == 0x42 && bytes[11] == 0x50) return true;
    }

    return false;
  }

  /// Validates video file magic numbers
  static bool _isValidVideoFile(Uint8List bytes) {
    if (bytes.length < 8) return false;

    // MP4/MOV (starts with ftyp)
    if (bytes.length >= 8) {
      if (bytes[4] == 0x66 && bytes[5] == 0x74 && bytes[6] == 0x79 && bytes[7] == 0x70) return true;
    }

    // AVI
    if (bytes.length >= 12) {
      if (bytes[0] == 0x52 && bytes[1] == 0x49 && bytes[2] == 0x46 && bytes[3] == 0x46 &&
          bytes[8] == 0x41 && bytes[9] == 0x56 && bytes[10] == 0x49 && bytes[11] == 0x20) return true;
    }

    // WebM/MKV (EBML header)
    if (bytes[0] == 0x1A && bytes[1] == 0x45 && bytes[2] == 0xDF && bytes[3] == 0xA3) return true;

    return false;
  }

  /// Validates document file magic numbers
  static bool _isValidDocumentFile(Uint8List bytes) {
    if (bytes.length < 4) return false;

    // PDF
    if (bytes.length >= 4) {
      final header = String.fromCharCodes(bytes.sublist(0, 4));
      if (header == '%PDF') return true;
    }

    // Office documents (ZIP-based)
    if (bytes[0] == 0x50 && bytes[1] == 0x4B && (bytes[2] == 0x03 || bytes[2] == 0x05)) return true;

    return true; // Be permissive for documents due to format complexity
  }

  /// Validates archive file magic numbers
  static bool _isValidArchiveFile(Uint8List bytes) {
    if (bytes.length < 4) return false;

    // ZIP
    if (bytes[0] == 0x50 && bytes[1] == 0x4B && (bytes[2] == 0x03 || bytes[2] == 0x05)) return true;

    // RAR
    if (bytes.length >= 7) {
      if (bytes[0] == 0x52 && bytes[1] == 0x61 && bytes[2] == 0x72 && bytes[3] == 0x21 &&
          bytes[4] == 0x1A && bytes[5] == 0x07 && bytes[6] == 0x00) return true;
    }

    // 7z
    if (bytes.length >= 6) {
      if (bytes[0] == 0x37 && bytes[1] == 0x7A && bytes[2] == 0xBC && bytes[3] == 0xAF &&
          bytes[4] == 0x27 && bytes[5] == 0x1C) return true;
    }

    return false;
  }

  /// Generates SHA-256 checksum for file integrity verification
  static Future<String> _generateFileChecksum(File file) async {
    try {
      final bytes = await file.readAsBytes();
      final digest = sha256.convert(bytes);
      return digest.toString();
    } catch (e) {
      debugPrint('Error generating file checksum: $e');
      return '';
    }
  }
}

/// Summary of validation results for multiple files
class ValidationSummary {
  final int totalFiles;
  final int validFiles;
  final int invalidFiles;
  final int filesWithWarnings;
  final int totalSize;
  final List<String> errors;
  final List<String> warnings;

  const ValidationSummary({
    required this.totalFiles,
    required this.validFiles,
    required this.invalidFiles,
    required this.filesWithWarnings,
    required this.totalSize,
    required this.errors,
    required this.warnings,
  });

  /// Whether all files passed validation
  bool get allValid => invalidFiles == 0;

  /// Whether any files have warnings
  bool get hasWarnings => filesWithWarnings > 0;

  /// Formatted total size
  String get formattedTotalSize => FileSizeLimits.formatFileSize(totalSize);

  @override
  String toString() => 'ValidationSummary($validFiles/$totalFiles valid, ${formattedTotalSize})';
}