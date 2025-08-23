
# RCEPayloadGen - Advanced RCE Payload Generator

RCEPayloadGen is a comprehensive Remote Code Execution payload generator designed for penetration testers, security researchers, and red teamers. This tool generates a wide variety of RCE payloads tailored to different environments, contexts, and encoding methods.

## Features

- **Multi-Environment Support**: Generate payloads for Unix, Windows, PHP, Python, Java, and JavaScript environments
- **Context-Aware**: Creates payloads for different injection contexts (HTML, JavaScript, SQL, etc.)
- **Advanced Encoding**: Multiple encoding methods including Base64, Hex, ROT13, URL encoding, and more
- **Customizable**: Fine-tune payload generation with various command-line options
- **Production-Ready**: Robust error handling, logging, and performance optimization
- **No Duplicates**: Intelligent duplicate detection to avoid redundant payloads

## Installation

```bash
# Clone the repository
git clone https://github.com/ahmad-kabiri/rcpayloadgen.git
cd rcpayloadgen

# Install dependencies (none required beyond standard Python libraries)
# Python 3.6+ required
```

## Usage

```bash
python rce_payload_gen.py [OPTIONS]
```

### Basic Examples

Generate all payloads with default settings:
```bash
python rce_payload_gen.py
```

Generate only Unix reverse shells with base64 encoding:
```bash
python rce_payload_gen.py --categories reverse_shells --environments unix --encodings base64
```

Generate up to 1000 payloads for PHP contexts:
```bash
python rce_payload_gen.py --contexts php --max-payloads 1000
```

Use custom attacker IP and domain:
```bash
python rce_payload_gen.py --attacker-ip 10.0.0.1 --attacker-domain evil.com
```

### Full Options

| Option | Description | Default |
|--------|-------------|---------|
| `-o, --output` | Output file path | `rce_payloads.txt` |
| `--attacker-ip` | Attacker IP for reverse shells | `192.168.1.100` |
| `--attacker-domain` | Attacker domain for download payloads | `attacker.com` |
| `--max-payloads` | Maximum number of payloads to generate | Unlimited |
| `--contexts` | Contexts to generate (space-separated) | All contexts |
| `--categories` | Categories to generate (space-separated) | All categories |
| `--encodings` | Encoding methods to apply (space-separated) | All encodings |
| `--environments` | Environments to generate (space-separated) | All environments |

### Available Contexts

- `html` - HTML context
- `attribute` - HTML attribute context
- `javascript` - JavaScript context
- `sql` - SQL injection context
- `php` - PHP code context
- `unix_shell` - Unix shell context
- `windows_cmd` - Windows command context
- `powershell` - PowerShell context

### Available Categories

- `basic_enum` - Basic enumeration commands
- `file_operations` - File system operations
- `network_operations` - Network reconnaissance
- `code_execution` - Language-specific code execution
- `download_execute` - Download and execute payloads
- `reverse_shells` - Reverse shell payloads

### Available Encoding Methods

- `none` - No encoding
- `url_encode` - URL encoding
- `double_url_encode` - Double URL encoding
- `base64` - Base64 encoding
- `hex` - Hexadecimal encoding
- `rot13` - ROT13 encoding
- `random_case` - Random case variation
- `insert_special_chars` - Insert special characters

## Payload Types

RCEPayloadGen generates payloads across multiple categories:

1. **Basic Enumeration**: Common system reconnaissance commands
2. **File Operations**: File system interaction and sensitive file access
3. **Network Operations**: Network configuration and discovery
4. **Code Execution**: Language-specific code execution patterns
5. **Download & Execute**: Payloads that download and execute remote code
6. **Reverse Shells**: Comprehensive reverse shell payloads for various environments

## Logging

The tool generates detailed logs in `rce_generator.log` with timestamps and severity levels to help with debugging and monitoring the generation process.

## Ethical Use

This tool is intended for:

- Penetration testing with proper authorization
- Security research and education
- Defensive security training
- Security tool development

**Never use this tool against systems without explicit permission.** Unauthorized testing is illegal and unethical.

## Contributing

Contributions are welcome! Please feel free to submit pull requests with:

- New payload categories
- Additional encoding methods
- Bug fixes
- Performance improvements
- Documentation enhancements

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is provided for educational and authorized testing purposes only. The developers are not responsible for any misuse or damage caused by this program.
