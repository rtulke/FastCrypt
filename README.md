# FastCrypt v2.0

A modern, cross-platform encryption application with advanced cryptographic features, built with Python and Tkinter.

## Features

### Core Encryption
- **Modern Algorithms**: AES-256-GCM, ChaCha20-Poly1305 (when cryptography library available)
- **Fallback Support**: Works with Python standard library only
- **Secure Key Derivation**: HKDF and PBKDF2 with 100,000 iterations
- **Cross-Platform**: Works on Linux, macOS, and Windows

### Digital Signatures
- **RSA-PSS**: Industry standard RSA signatures with PSS padding
- **Ed25519**: Modern elliptic curve signatures
- **Key Management**: Generate, save, load key pairs
- **Signature Verification**: Verify signatures with public keys

### Key Exchange Protocols
- **ECDH-P256**: Elliptic Curve Diffie-Hellman with P-256 curve
- **ECDH-P384**: Elliptic Curve Diffie-Hellman with P-384 curve
- **Secure Key Derivation**: HKDF for final shared secret
- **Public Key Sharing**: Easy exchange of public keys

### User Interface
- **Modern GUI**: Clean, responsive tabbed interface
- **Dark/Light Themes**: Toggle between themes
- **Real-time Feedback**: Character counter, status messages
- **Email Integration**: Send encrypted messages via default email client
- **Copy/Paste Support**: Full clipboard integration
- **File Operations**: Save/load keys and messages

### Security Features
- **No Local Storage**: Everything stays in memory during runtime
- **Secure Random Generation**: Cryptographically secure salt and keys
- **Memory-Only Operation**: No persistent data storage
- **Constant-Time Operations**: HMAC comparisons use constant-time functions

## Installation

### Quick Start (Basic Features)
```bash
git clone https://gitlab.com/rtulke/fastcrypt.git
cd fastcrypt
python3 fastcrypt.py
```

### Full Installation (All Features)
```bash
git clone https://gitlab.com/rtulke/fastcrypt.git
cd fastcrypt

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run application
python3 fastcrypt.py
```

### Development Setup
```bash
# Install development tools
pip install -r requirements.txt

# Run tests
python -m pytest tests/

# Code formatting
black fastcrypt.py

# Type checking
mypy fastcrypt.py

# Security scanning
bandit fastcrypt.py
safety check
```

## Usage

### Encryption/Decryption
1. Select algorithm from **Encryption** tab
2. Enter password or generate random salt
3. Paste/type text in input field
4. Click **Encrypt** or **Decrypt**
5. Copy result or send via email

### Digital Signatures
1. Go to **Signatures** tab
2. Select algorithm (RSA-PSS or Ed25519)
3. Generate or load key pair
4. Enter message and click **Sign Message**
5. Share signature and public key
6. Verify with **Load Public Key** + **Verify Signature**

### Key Exchange
1. Go to **Key Exchange** tab
2. Select protocol (ECDH-P256 or ECDH-P384)
3. Generate key pair
4. Share your public key with peer
5. Paste peer's public key
6. Click **Perform Key Exchange**
7. Use shared secret for encryption

## Keyboard Shortcuts

- `Ctrl+C` / `Cmd+C`: Copy selected text
- `Ctrl+V` / `Cmd+V`: Paste from clipboard

## Themes

Switch between light and dark mode:
- **Menu**: View → Toggle Dark Mode

## Security Notice

⚠️ **Cryptography Library Required**: For production security, install the `cryptography` library. The fallback mode uses only Python standard library and provides limited security.

**Secure algorithms** (requires cryptography):
- AES-256-GCM
- ChaCha20-Poly1305
- RSA-PSS signatures
- Ed25519 signatures
- ECDH key exchange

**Fallback algorithms** (standard library only):
- HMAC-SHA256 (authentication only)
- XOR cipher (NOT secure)
- Base64 encoding (NOT encryption)

## Architecture

### Code Structure
- **Single File**: Complete application in `fastcrypt.py`
- **Modular Design**: Separate classes for crypto, themes, key management
- **Error Handling**: Comprehensive exception handling
- **Type Hints**: Full type annotations for better code quality

### Classes
- `FastCrypt`: Main application class
- `CryptoEngine`: All cryptographic operations
- `ThemeManager`: Light/dark theme management
- `KeyPair`: Container for asymmetric key pairs

### Security Design
- Memory-only operation (no persistent storage)
- Secure random number generation
- Proper key derivation with salts
- Constant-time comparisons for HMAC
- Exception handling prevents information leakage

## System Requirements

- **Python**: 3.8 or higher
- **Operating System**: Linux, macOS, Windows
- **Memory**: 50MB minimum
- **Dependencies**: See `requirements.txt`
- **Optional**: `cryptography` library for full features

## Performance

- **Startup Time**: < 2 seconds
- **Encryption**: Real-time for text up to 1MB
- **Key Generation**: 1-5 seconds depending on algorithm
- **Memory Usage**: < 100MB during operation

## Development

### Code Standards
- Follow PEP 8 style guidelines
- Use type hints for all functions
- Keep functions under 50 lines
- Comments in English
- Variables in UPPERCASE for constants
- Modular design with single responsibility

### Testing
```bash
# Run all tests
python -m pytest tests/ -v

# Test specific module
python -m pytest tests/test_crypto.py

# Coverage report
python -m pytest --cov=fastcrypt tests/
```

### Security Testing
```bash
# Security vulnerability scanning
bandit -r fastcrypt.py

# Dependency vulnerability check
safety check

# Static analysis
pylint fastcrypt.py
```

## API Reference

### CryptoEngine Methods
```python
# Encryption
def aes_gcm_cipher(text: str, password: str, salt: bytes, encrypt: bool) -> str
def chacha20_cipher(text: str, password: str, salt: bytes, encrypt: bool) -> str

# Signatures
def generate_rsa_keypair() -> KeyPair
def rsa_pss_sign(message: str, private_key: bytes, verify: bool = False) -> str

# Key Exchange
def generate_ecdh_keypair(curve: str) -> KeyPair
def ecdh_exchange(private_key: bytes, peer_public_key: bytes) -> str
```

## Author

**Robert Tulke**
- Email: rt@debian.sh
- Website: https://tulke.ch
- Repository: https://gitlab.com/rtulke/fastcrypt/

## License

This project is open source. See repository for license details.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Follow code standards and add tests
4. Commit changes (`git commit -m 'Add amazing feature'`)
5. Push to branch (`git push origin feature/amazing-feature`)
6. Submit a pull request

### Contribution Guidelines
- Write tests for new features
- Maintain backward compatibility
- Follow security best practices
- Update documentation
- Add type hints

## Roadmap

### Version 2.1
- [ ] File encryption/decryption
- [ ] Batch processing
- [ ] Configuration file support
- [ ] Plugin architecture

### Version 2.2
- [ ] Network protocols (TLS-like)
- [ ] Hardware security module support
- [ ] Multi-language support
- [ ] Advanced key management

### Version 3.0
- [ ] Post-quantum cryptography
- [ ] Zero-knowledge proofs
- [ ] Distributed key management
- [ ] Mobile app version

## Changelog

### v2.0 (Current)
- Added digital signatures (RSA-PSS, Ed25519)
- Added key exchange protocols (ECDH)
- Added dark/light theme support
- Improved security with modern algorithms
- Enhanced GUI with tabbed interface
- Added comprehensive error handling

### v1.0
- Basic encryption/decryption
- Email integration
- Copy/paste support
- Cross-platform compatibility

## Security Audit

Last security review: Never (community project)

**Recommendations for production use:**
1. Professional security audit
2. Formal verification of critical functions
3. Hardware security module integration
4. Regular dependency updates
5. Penetration testing

## Disclaimer

This software is provided "as is" without warranty of any kind. Use at your own risk. While designed with security best practices, no formal security audit has been performed. Not recommended for protecting highly sensitive data without independent security review.

## Support

- **Bug Reports**: Use GitLab issues
- **Questions**: Email rt@debian.sh
- **Documentation**: See inline help and code comments
- **Security Issues**: Contact author directly

## Acknowledgments

- Python cryptography library team
- Tkinter GUI framework
- Security research community
- Open source contributors
