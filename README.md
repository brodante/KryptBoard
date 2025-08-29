# Secure IME - Android Input Method Editor

A secure Android keyboard built with Kotlin, Jetpack Compose, and Material 3.

## Features

- **Security First**: No internet permissions, no keystroke logging
- **Encryption Support**: Built-in text encryption using ChaCha20-Poly1305 (stub implementation)
- **Modern UI**: Material 3 design with Jetpack Compose
- **Two Modes**:
  - **Plain Mode**: Keys commit text directly to the target app
  - **Encrypted Mode**: Text is buffered, encrypted, and sent as ciphertext envelope

## Project Structure

```
├── settings.gradle.kts              # Project configuration
├── build.gradle.kts                 # Root build configuration  
├── gradle/wrapper/                  # Gradle wrapper files
├── gradlew                          # Gradle wrapper script (Unix)
├── gradlew.bat                      # Gradle wrapper script (Windows)
├── local.properties                 # Local SDK configuration
├── app-ime/                         # Main IME application module
│   ├── build.gradle.kts            # App module build configuration
│   ├── proguard-rules.pro          # ProGuard rules for release builds
│   └── src/main/
│       ├── AndroidManifest.xml     # App manifest with IME service declaration
│       ├── res/
│       │   ├── values/strings.xml  # String resources
│       │   └── xml/method.xml      # IME method configuration
│       └── java/com/example/secureime/
│           ├── ime/
│           │   └── SecureKeyboardService.kt    # Main IME service
│           └── ui/
│               ├── KeyboardRoot.kt             # Main keyboard UI
│               ├── Keys.kt                     # Key button components
│               └── SettingsActivity.kt         # Settings screen
├── crypto-lib/                      # Cryptography library module
│   ├── build.gradle.kts            # Library build configuration
│   └── src/main/java/com/example/cryptolib/
│       ├── StreamCipher.kt         # Encryption interface
│       ├── CipherOut.kt            # Encryption output data class
│       ├── ChaCha20Poly1305Stub.kt # ChaCha20-Poly1305 stub implementation
│       ├── AesCtrHmacStub.kt       # AES-CTR-HMAC stub implementation
│       ├── Base64Url.kt            # Base64URL encoding utilities
│       └── Envelope.kt             # Ciphertext envelope serialization
└── baselineprofile/                 # Baseline profile for performance
    ├── build.gradle.kts            # Baseline profile build configuration
    └── src/main/java/com/example/baseline/
        └── BaselineProfileGenerator.kt    # Profile generation tests
```

## Setup Instructions

### Prerequisites

- Android Studio Arctic Fox or later
- Android SDK 35
- Java 17 or later

### Building the Project

1. **Download Gradle Wrapper** (if gradle-wrapper.jar is missing):
   ```bash
   ./gradlew wrapper
   ```

2. **Open in Android Studio**:
   - Launch Android Studio
   - Choose "File" → "Open"
   - Select the project root directory
   - Wait for Gradle sync to complete

3. **Build the Project**:
   ```bash
   ./gradlew build
   ```

### Installing and Testing

1. **Install the App**:
   ```bash
   ./gradlew installDebug
   ```

2. **Enable the Keyboard**:
   - Go to Settings → System → Languages & input
   - Select "On-screen keyboard" → "Manage keyboards" 
   - Toggle "Secure IME" to enable

3. **Test the Keyboard**:
   - Open any text field in any app
   - Long-press the text field and select "Input method"
   - Choose "Secure IME"
   - Test both Plain and Encrypted modes

## Security Features

- ✅ No `INTERNET` permission in manifest
- ✅ No network calls in code
- ✅ No keystroke logging
- ✅ `FLAG_SECURE` prevents screenshots in settings
- ✅ Local-only encryption (stub implementation)
- ✅ ProGuard/R8 enabled for release builds

## Usage

### Plain Mode
- Keys commit text directly to the target application
- Immediate text input with no buffering

### Encrypted Mode  
- Text is buffered in the top text field
- Use "Encrypt & Send" button to encrypt and commit ciphertext
- Ciphertext format: `v1|algorithm|nonce|ciphertext|tag` (base64url encoded)

## Development Notes

- **Target SDK**: 35
- **Min SDK**: 26
- **Compile SDK**: 35
- **Kotlin Version**: 2.0.20
- **Gradle Version**: 8.5
- **Compose BOM**: 2024.10.01

## TODO for Production

- Replace stub crypto implementations with real encryption
- Add more keyboard layouts and languages
- Implement proper key management
- Add more sophisticated input features (autocorrect, suggestions, etc.)
- Comprehensive testing and security audit

## License

This project is for educational/demonstration purposes.
