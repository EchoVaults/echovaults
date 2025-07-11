// lib/security/privacy_levels.dart
//
// EchoVaults Transparency Repository
// Privacy Levels & Access Control Logic
//
// This file defines the three privacy levels in EchoVaults and controls
// who can access what data under what circumstances.
//
// Privacy Levels:
// - Basic: Immediate access for trusted persons after security questions
// - Sensitive: Delayed access for trusted persons (configurable delay)
// - Ultra: Owner-only access, never accessible to trusted persons
//

import 'dart:async';

/// Enumeration of privacy levels available in EchoVaults
enum PrivacyLevel {
  /// Basic privacy - accessible immediately by trusted persons after security verification
  basic('basic'),

  /// Sensitive privacy - accessible by trusted persons after configurable delay
  sensitive('sensitive'),

  /// Ultra privacy - accessible only by owner, never by trusted persons
  ultra('ultra');

  const PrivacyLevel(this.value);
  final String value;

  /// Convert string to privacy level enum
  static PrivacyLevel fromString(String value) {
    switch (value.toLowerCase()) {
      case 'basic':
        return PrivacyLevel.basic;
      case 'sensitive':
        return PrivacyLevel.sensitive;
      case 'ultra':
        return PrivacyLevel.ultra;
      default:
        return PrivacyLevel.basic; // Default to most permissive
    }
  }
}

/// User types that can access the system
enum UserType {
  /// Vault owner - full access to all vaults and settings
  owner('owner'),

  /// Trusted person - limited access based on privacy levels and timing
  trusted('trusted'),

  /// Unauthenticated - no access
  none('none');

  const UserType(this.value);
  final String value;
}

/// Core access control logic for EchoVaults privacy system
///
/// This class implements the fundamental rules that govern who can access
/// what data under what circumstances. These rules are the foundation
/// of EchoVaults' privacy promise to users.
class PrivacyAccessControl {

  /// Checks if a user can access a vault based on privacy level and current state
  ///
  /// This is the central method that enforces EchoVaults privacy rules:
  /// - Owners can always access their own vaults (with master password)
  /// - Trusted persons can access basic vaults immediately after security questions
  /// - Trusted persons can access sensitive vaults after configured delay
  /// - Trusted persons can never access ultra vaults
  ///
  /// [userType] Type of user requesting access
  /// [privacyLevel] Privacy level of the vault being accessed
  /// [vaultId] Unique identifier of the vault
  /// [unlockTime] When trusted person passed security questions (null if not unlocked)
  /// [sensitiveDelayHours] Hours to wait for sensitive vault access (0 = immediate)
  ///
  /// Returns: true if access is allowed, false otherwise
  static bool canAccessVault({
    required UserType userType,
    required PrivacyLevel privacyLevel,
    required String vaultId,
    DateTime? unlockTime,
    int sensitiveDelayHours = 24,
  }) {
    // Owner has full access to all their vaults (password verification handled elsewhere)
    if (userType == UserType.owner) {
      return true;
    }

    // Unauthenticated users have no access
    if (userType == UserType.none) {
      return false;
    }

    // Trusted person access rules
    if (userType == UserType.trusted) {
      switch (privacyLevel) {
        case PrivacyLevel.basic:
        // Basic vaults: accessible immediately after security questions
          return unlockTime != null;

        case PrivacyLevel.sensitive:
        // Sensitive vaults: accessible after delay period
          if (unlockTime == null) {
            return false; // Haven't passed security questions yet
          }

          // If delay is 0, access is immediate
          if (sensitiveDelayHours == 0) {
            return true;
          }

          // Check if enough time has passed
          final requiredWaitTime = Duration(hours: sensitiveDelayHours);
          final accessTime = unlockTime.add(requiredWaitTime);
          return DateTime.now().isAfter(accessTime);

        case PrivacyLevel.ultra:
        // Ultra vaults: never accessible to trusted persons
          return false;
      }
    }

    return false;
  }

  /// Calculates remaining wait time for sensitive vault access
  ///
  /// [unlockTime] When trusted person passed security questions
  /// [sensitiveDelayHours] Hours to wait for access
  ///
  /// Returns: Remaining wait time, or null if no wait required
  static Duration? getRemainingWaitTime({
    required DateTime unlockTime,
    required int sensitiveDelayHours,
  }) {
    // No wait required if delay is 0
    if (sensitiveDelayHours == 0) {
      return null;
    }

    final requiredWaitTime = Duration(hours: sensitiveDelayHours);
    final accessTime = unlockTime.add(requiredWaitTime);
    final now = DateTime.now();

    if (now.isAfter(accessTime)) {
      return null; // Wait period is over
    }

    return accessTime.difference(now);
  }

  /// Checks if a user can perform a specific action
  ///
  /// Actions are more granular than vault access and include system operations
  /// like editing settings, deleting vaults, or managing security questions.
  ///
  /// [userType] Type of user requesting action
  /// [action] Specific action being requested
  ///
  /// Returns: true if action is allowed, false otherwise
  static bool canPerformAction({
    required UserType userType,
    required VaultAction action,
  }) {
    if (userType == UserType.owner) {
      // Owners can perform all actions
      return true;
    }

    if (userType == UserType.trusted) {
      // Trusted persons have limited privileges
      switch (action) {
        case VaultAction.viewVault:
          return true; // Can view accessible vaults
        case VaultAction.exportVault:
          return true; // Can export accessible vaults
        case VaultAction.editVault:
        case VaultAction.deleteVault:
        case VaultAction.editSettings:
        case VaultAction.editSecurityQuestions:
        case VaultAction.createVault:
          return false; // Cannot modify anything
      }
    }

    return false; // Default deny
  }

  /// Validates that privacy level configuration is valid
  ///
  /// [privacyLevel] Privacy level to validate
  /// [sensitiveDelayHours] Delay hours for sensitive vaults
  ///
  /// Returns: true if configuration is valid
  static bool isValidPrivacyConfiguration({
    required PrivacyLevel privacyLevel,
    int? sensitiveDelayHours,
  }) {
    switch (privacyLevel) {
      case PrivacyLevel.basic:
      case PrivacyLevel.ultra:
      // Basic and ultra don't use delay settings
        return true;

      case PrivacyLevel.sensitive:
      // Sensitive vaults must have valid delay configuration
        if (sensitiveDelayHours == null) {
          return false;
        }

        // Valid delay periods (in hours)
        const validDelays = [
          0,      // Immediate
          12,     // 12 hours
          24,     // 1 day
          72,     // 3 days
          168,    // 1 week
          336,    // 2 weeks
          720,    // 1 month
          4320,   // 6 months
          8760,   // 1 year
          26280,  // 3 years
          43800,  // 5 years
          87600,  // 10 years
        ];

        return validDelays.contains(sensitiveDelayHours);
    }
  }

  /// Gets human-readable description of privacy level
  ///
  /// [privacyLevel] Privacy level to describe
  /// [sensitiveDelayHours] Delay for sensitive vaults
  ///
  /// Returns: User-friendly description
  static String getPrivacyDescription({
    required PrivacyLevel privacyLevel,
    int? sensitiveDelayHours,
  }) {
    switch (privacyLevel) {
      case PrivacyLevel.basic:
        return 'Available immediately after security questions are answered correctly';

      case PrivacyLevel.sensitive:
        if (sensitiveDelayHours == null || sensitiveDelayHours == 0) {
          return 'Available immediately after security questions are answered correctly';
        }

        final delayDescription = _formatDelayHours(sensitiveDelayHours);
        return 'Available $delayDescription after security questions are answered correctly';

      case PrivacyLevel.ultra:
        return 'Only accessible by the owner with master password. Never accessible to trusted persons';
    }
  }

  /// Formats delay hours into human-readable format
  static String _formatDelayHours(int hours) {
    if (hours == 0) return 'immediately';
    if (hours < 24) return '$hours hours';
    if (hours == 24) return '1 day';
    if (hours == 72) return '3 days';
    if (hours == 168) return '1 week';
    if (hours == 336) return '2 weeks';
    if (hours == 720) return '1 month';
    if (hours == 4320) return '6 months';
    if (hours == 8760) return '1 year';
    if (hours == 26280) return '3 years';
    if (hours == 43800) return '5 years';
    if (hours == 87600) return '10 years';

    final days = hours ~/ 24;
    return '$days days';
  }
}

/// Enumeration of actions that can be performed in the vault system
enum VaultAction {
  /// View vault contents
  viewVault,

  /// Edit vault contents
  editVault,

  /// Delete a vault
  deleteVault,

  /// Create a new vault
  createVault,

  /// Export vault data
  exportVault,

  /// Edit system settings
  editSettings,

  /// Edit security questions
  editSecurityQuestions,
}

/// Represents the state of vault access for a trusted person
class TrustedPersonAccessState {
  /// When the trusted person successfully passed security questions
  final DateTime? unlockTime;

  /// Map of vault ID to individual unlock times (for per-vault delays)
  final Map<String, DateTime> vaultUnlockTimes;

  /// Full name of the trusted person (for logging/display)
  final String? trustedPersonName;

  const TrustedPersonAccessState({
    this.unlockTime,
    this.vaultUnlockTimes = const {},
    this.trustedPersonName,
  });

  /// Checks if this trusted person has unlocked vault access
  bool get isUnlocked => unlockTime != null;

  /// Gets unlock time for a specific vault (falls back to global unlock time)
  DateTime? getVaultUnlockTime(String vaultId) {
    return vaultUnlockTimes[vaultId] ?? unlockTime;
  }

  /// Creates a copy with updated unlock time for a specific vault
  TrustedPersonAccessState withVaultUnlock(String vaultId, DateTime unlockTime) {
    final updatedTimes = Map<String, DateTime>.from(vaultUnlockTimes);
    updatedTimes[vaultId] = unlockTime;

    return TrustedPersonAccessState(
      unlockTime: this.unlockTime ?? unlockTime,
      vaultUnlockTimes: updatedTimes,
      trustedPersonName: trustedPersonName,
    );
  }

  /// Resets all unlock state (owner has returned)
  TrustedPersonAccessState reset() {
    return const TrustedPersonAccessState();
  }
}