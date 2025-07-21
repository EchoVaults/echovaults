# EchoVaults Privacy Architecture

## Philosophy

EchoVaults is built on the principle that **privacy is a spectrum, not a binary**. Different types of information require different levels of protection, and users should have granular control over who can access what, and when.

Our privacy architecture recognizes that in end-of-life scenarios, the balance between **security** and **accessibility** must be carefully calibrated based on the sensitivity of the content and the user's intentions.

## The Three Privacy Levels

### Basic Privacy
**"They can see this right away if something happens to me"**

- **Purpose**: Information that trusted persons should access immediately
- **Examples**: Emergency contacts, basic instructions, non-sensitive messages
- **Access Control**: Available immediately after security questions are answered
- **Technical Implementation**: Base64 encoding with integrity checksums
- **User Intent**: "I want my family to have this information quickly in an emergency"

```
Timeline: Owner Passes → Trusted Person Finds Phone → Answers Security Questions → Immediate Access
```

### Sensitive Privacy
**"They can see this, but only after thinking about it"**

- **Purpose**: More personal content that requires a "cooling off" period
- **Examples**: Personal letters, family secrets, sensitive accounts
- **Access Control**: Available after configurable delay (hours to years)
- **Technical Implementation**: Base64 encoding, access controlled by timestamps
- **User Intent**: "I want them to have this, but with time to consider the weight of it"

```
Timeline: Owner Passes → Security Questions → Wait Period → Access Granted
```

**Configurable Delays:**
- Immediate (0 hours) - for urgent sensitive information
- 12 hours - for personal messages
- 1 day - for private thoughts
- 3 days - for family discussions
- 1 week - for significant disclosures
- 1 month - for major life revelations
- 6 months to 10 years - for generational secrets

### Ultra Sensitive Privacy
**"This is for me only, never for anyone else"**

- **Purpose**: Completely private information that should never be shared
- **Examples**: Therapy notes, private diaries, confidential business information
- **Access Control**: Owner only, requires master password, never accessible to trusted persons
- **Technical Implementation**: Full AES-256 encryption
- **User Intent**: "This dies with me, period"

```
Timeline: Only accessible by owner with master password → Never accessible to others
```

## Privacy Decision Framework

When creating a vault, users are guided through this decision tree:

### Step 1: Who Should Access This?
- **Just Me**: → Ultra Sensitive
- **My Trusted Person(s)**: → Continue to Step 2

### Step 2: When Should They Access This?
- **Right Away (Emergency Info)**: → Basic
- **After Some Time to Process**: → Sensitive (choose delay)

### Step 3: What's the Right Delay? (For Sensitive)
- **How personal/shocking is this information?**
- **How much time should they have to emotionally prepare?**
- **What would you want if roles were reversed?**

## Technical Privacy Implementation

### Data Encryption Strategy

```dart
// Ultra Sensitive: Full AES-256 encryption
final encryptedData = AES256.encrypt(content, masterPasswordKey);

// Basic/Sensitive: Accessible encoding with integrity
final accessibleData = base64.encode(content) + checksum;
```

### Access Control Logic

```dart
bool canAccess(PrivacyLevel level, DateTime? unlockTime, int delayHours) {
  switch (level) {
    case PrivacyLevel.basic:
      return unlockTime != null; // Immediate after security questions
      
    case PrivacyLevel.sensitive:
      if (unlockTime == null) return false;
      if (delayHours == 0) return true;
      return DateTime.now().isAfter(unlockTime.add(Duration(hours: delayHours)));
      
    case PrivacyLevel.ultra:
      return false; // Never accessible to trusted persons
  }
}
```

### Privacy Inheritance Model

```
Owner's Privacy Intent
        ↓
Technical Implementation
        ↓
Trusted Person Experience
```

## Privacy vs. Security Trade-offs

### Designed Vulnerabilities

EchoVaults intentionally makes **Basic** and **Sensitive** vaults accessible without the master password. This is **not a security flaw** - it's a **privacy design decision**.

#### Why We Do This:
1. **Emergency Access**: In real emergencies, complex passwords create barriers
2. **Emotional Context**: Grieving people shouldn't struggle with technical obstacles
3. **User Intent**: Owners explicitly choose these levels knowing they're accessible
4. **Graduated Control**: Ultra level exists for truly private content

#### Security Measures We Still Maintain:
- Security questions prevent random access
- Time delays for sensitive content
- Integrity checksums prevent tampering
- Owner can reset access if they're still alive

### Trust Model

```
Owner Trust → Technical Implementation → Outcome

"I trust them with this immediately" → Basic Privacy → Immediate access
"I trust them with this eventually" → Sensitive Privacy → Delayed access  
"I don't trust anyone with this" → Ultra Privacy → Owner-only access
```

## Privacy UX Design

### Clear Mental Models

Users understand privacy levels through relatable analogies:

- **Basic**: "Like leaving a note on the kitchen table"
- **Sensitive**: "Like a sealed letter with 'open in 6 months' written on it"
- **Ultra**: "Like a diary with a lock that breaks when I die"

### Visual Privacy Indicators

- **Green**: "Open access" - Basic vaults
- **Yellow**: "Timed access" - Sensitive vaults
- **Red**: "Private access" - Ultra vaults

### Privacy Feedback

Users see exactly what their trusted person will experience:

```
"Sarah will see this message immediately after answering your security questions"

"Sarah will see this message 3 days after answering your security questions"

"Sarah will never see this message - it's private to you only"
```

## Privacy Rights and Controls

### Owner Rights (Always Preserved)
- View all vaults regardless of privacy level
- Change privacy levels at any time
- Reset trusted person access if alive
- Delete any vault permanently
- Export data in any format

### Trusted Person Rights (Limited by Design)
- View Basic vaults immediately after security questions
- View Sensitive vaults after configured delays
- Export accessible vault contents
- **Cannot**: Edit, delete, or change privacy settings
- **Cannot**: Access Ultra vaults under any circumstances

### Privacy Overrides

#### Owner Override
If the owner is still alive and detects unauthorized access:
```dart
void resetTrustedPersonAccess() {
  // Immediately revokes all trusted person access
  // Resets all countdown timers
  // Requires owner to re-authenticate
}
```

#### No System Override
There is **no administrative override**, **no backdoor**, and **no recovery mechanism** that bypasses user privacy choices.

## Privacy Scenarios

### Scenario 1: Medical Emergency
- **Need**: Family needs immediate access to medical info
- **Solution**: Medical information in Basic vaults
- **Privacy**: Other personal content in Sensitive/Ultra levels

### Scenario 2: Sudden Passing
- **Need**: Family needs access but owner had very private content
- **Solution**: Mix of Basic (immediate needs) and Sensitive (personal letters with delays)
- **Privacy**: Ultra vaults remain private forever

### Scenario 3: Family Reconciliation
- **Need**: Healing messages for estranged family members
- **Solution**: Sensitive vaults with long delays (months/years) to allow time for healing
- **Privacy**: Immediate practical needs in Basic vaults

### Scenario 4: Business Confidentiality
- **Need**: Personal vaults accessible to family, business info must stay private
- **Solution**: Personal content in Basic/Sensitive, business info in Ultra
- **Privacy**: Professional obligations respected even after death

## Privacy Auditing

### What Users Can Verify

1. **Code Transparency**: Full encryption logic is open source
2. **Local Storage**: All data stays on device, never uploaded
3. **Access Logs**: Users can see who accessed what and when
4. **Privacy Enforcement**: Technical implementation matches user intent

### What Developers Cannot Do

- Access user data (technical impossibility)
- Reset or recover passwords
- Override privacy settings
- See vault contents or metadata
- Identify which users have which types of content

## Privacy Evolution

### Changing Privacy Needs

Users can modify privacy levels at any time:

```dart
void changePrivacyLevel(String vaultId, PrivacyLevel newLevel) {
  // Re-encrypt content for new privacy level
  // Update access controls
  // Preserve user intent
}
```

### Privacy Migration

When moving devices or restoring backups:
- Privacy levels are preserved exactly
- No privacy degradation during transfer
- User must re-authenticate on new device

---

## Privacy Promise

**EchoVaults commits to:**

1. **Technical Privacy**: Your privacy is enforced by mathematics, not policies
2. **Granular Control**: You choose who sees what, and when
3. **Transparent Implementation**: You can verify how privacy works
4. **Respect for Intent**: Your privacy choices are permanently honored
5. **No Backdoors**: There is no way to bypass your privacy settings

**Your privacy is not a privilege we grant - it's a right we protect through technology.** 