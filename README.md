# Secure IME - Android Input Method Editor

A secure Android keyboard built with Kotlin, Jetpack Compose, and Material 3.

> **Browser build:** [`web-extension/`](web-extension/) contains KryptBoard as a
> Manifest V3 browser extension — the same buffered-keystroke design and the same
> `v1|alg|nonce|ct|tag` envelope, so ciphertext is interchangeable between the phone and
> the browser. It also implements the published paper's construction in full (a
> locally generated single-session key, Algorithm 1's `{nonce, ciphertext, tag}` output,
> buffer zeroization) and adds a **⌨ Capture** toggle that routes an external keyboard's
> keystrokes into the extension's buffer so the page never sees them. See
> [`web-extension/README.md`](web-extension/README.md) for the threat model, the crypto
> construction and the test suite.

**Paper:** S. P. S. Chauhan, S. Saha, P. Biswas, N. Kar, *Secure Your Words Before You Send:
the KryptBoard Pre-Send Encryption Method*, 2026 International Conference on Emerging Trends
and Innovations in ICT (ICEI), Pune, India, pp. 1–6.
[doi:10.1109/ICEI65890.2026.11447792](https://doi.org/10.1109/ICEI65890.2026.11447792)
· [`CITATION.cff`](CITATION.cff)

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
├── baselineprofile/                 # Baseline profile for performance
│   ├── build.gradle.kts            # Baseline profile build configuration
│   └── src/main/java/com/example/baseline/
│       └── BaselineProfileGenerator.kt    # Profile generation tests
└── web-extension/                   # Browser sibling of the IME (Manifest V3)
    ├── manifest.json               # permissions: ["storage"] — no host permissions
    ├── bundle/content.js           # generated content script (settings+crypto+keyboard)
    ├── src/                        # crypto.js, keyboard.js/.css, wiring.js, content.js, popup.*
    ├── demo/demo.html              # live demo using the real modules
    └── tests/                      # RFC vectors, DOM integration, packaging checks
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

The browser build in `web-extension/` holds the same line: `permissions: ["storage"]`,
no host permissions, no `fetch`/`XMLHttpRequest`/`WebSocket`/`eval` anywhere in the
shipped sources, a closed shadow root around the plaintext buffer, password fields
excluded as targets, and a test suite that fails if any of that changes.

### Envelope interoperability

Both implementations use the same serialisation, so a message sealed on one side opens
on the other:

```
v1|CHACHA20-POLY1305|<nonce>|<ciphertext>|<tag>        all base64url, unpadded
```

The browser test suite pins this format with golden vectors whose derived keys were
recomputed independently with Python's `hashlib`/`hmac` (`web-extension/tests/crypto.test.mjs`),
which is the reference to check the Kotlin side against.

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

---

Made with love by [d4nte](https://github.com/brodante/)

愛をこめて [ダンテ](https://github.com/brodante/) が作りました
