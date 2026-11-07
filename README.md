# TW1N

**TW1N** is a cross-platform, private, local-first AI assistant with document RAG, voice input, speech output, Tor integration, security monitoring, encrypted logs, audit trail, and 2FA.

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-brightgreen)

## Features

- Chat with OpenAI-compatible models through Groq
- Local RAG for TXT, Markdown, PDF and DOCX
- Voice input and text-to-speech
- Private chat mode
- Dark and light UI themes
- Tor proxy support
- Tor SAFECOOKIE authentication
- Tor IP rotation
- DNS and web leak checks
- Tor speed test
- Real-time traffic monitoring
- Security dashboard
- PDF and HTML dashboard export
- Encrypted security logs
- Encrypted ZIP log export
- Audit log with hash-chain integrity
- PIN and TOTP 2FA protection
- System tray support

## Quick start

### Windows

```powershell
git clone [https://github.com/yersagate/TW1N.git](https://github.com/yersagate/TW1N.git)
cd TW1N

python -m venv .venv
.venv\Scripts\activate

python -m pip install --upgrade pip
python -m pip install -r requirements.txt

setx GROQ_API_KEY "your_groq_api_key"
python app.py
```

### macOS / Linux

```bash
git clone [https://github.com/yersagate/TW1N.git](https://github.com/yersagate/TW1N.git)
cd TW1N

python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -r requirements.txt

export GROQ_API_KEY='your_groq_api_key'
python app.py
```

## Tor support

TW1N can route supported requests through a local Tor SOCKS proxy.

1. Install and start Tor Browser.
2. In TW1N, enable **Use Tor proxy**.
3. TW1N will detect Tor on port `9050` or `9150`.
4. You can also enter a custom SOCKS port.

For ControlPort features such as IP rotation and circuit diagnostics, enable Tor ControlPort and SAFECOOKIE authentication.

Tor Browser is available for Windows, macOS, and Linux.

## Security

TW1N includes:

- Fernet-encrypted security logs
- AES-256 encrypted ZIP exports
- Append-only audit log
- Hash-chain audit integrity verification
- PIN protection
- TOTP two-factor authentication
- Private chat mode

**Important:** Tor hides your IP address, but it does not hide the content of requests sent to third-party AI providers. Use Zero Data Retention and avoid sending sensitive information.

## Requirements

- Python 3.10+
- Windows, macOS, or Linux
- Tor Browser, optional
- Groq API key

## License

This project is licensed under the [MIT License](LICENSE).
