# RCEPayloadGen - Advanced RCE Payload Generator

RCEPayloadGen is a comprehensive Remote Code Execution payload generator designed for penetration testers, security researchers, and red teamers. This tool generates a wide variety of RCE payloads tailored to different environments, contexts, encoding methods, and specific execution sinks.

## Features

- **Multi-Environment Support**: Generate payloads for Unix, Windows, Node.js, Python, PHP, Java, .NET, Ruby, Perl, Go, and JavaScript environments
- **Context-Aware**: Creates payloads for different injection contexts (HTML, JavaScript, SQL, etc.)
- **Sink-Specific Payloads**: Detailed granularity for code execution sinks, including OS commands, template engines (SSTI), and language-specific execution methods with automatic constraint handling (e.g., escaping forbidden characters, adding quotes)
- **Advanced Encoding**: Multiple encoding methods including Base64, Hex, ROT13, URL encoding, and more
- **Customizable**: Fine-tune payload generation with various command-line options
- **No Duplicates**: Intelligent duplicate detection to avoid redundant payloads
- **Production-Ready**: Robust error handling, logging, and performance optimization

## Installation

```bash
# Clone the repository
git clone https://github.com/kabiri-labs/rcpayloadgen.git
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
- `code_execution` - Language-specific code execution (with sink-level granularity)
- `download_execute` - Download and execute payloads
- `reverse_shells` - Reverse shell payloads

### Available Environments

- `unix` - Unix-like systems
- `windows` - Windows systems
- `nodejs` - Node.js environment
- `python` - Python environment
- `php` - PHP environment
- `java` - Java/JVM environment
- `dotnet` - .NET environment
- `ruby` - Ruby environment
- `perl` - Perl environment
- `go` - Go environment
- `javascript` - JavaScript environment (legacy)

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
4. **Code Execution**: Language-specific code execution patterns with sink-level details and constraint adjustments
5. **Download & Execute**: Payloads that download and execute remote code
6. **Reverse Shells**: Comprehensive reverse shell payloads for various environments

## Detailed Code Execution Sinks

For the `code_execution` category, payloads are generated at a sink-specific level, with automatic adjustments for constraints such as forbidden characters (escaped via URL encoding) and quote requirements. Below is a list of supported sinks per environment:

### Node.js (`nodejs`)
- `child_process_exec`: Executions using child_process module
- `pug_ssti`: Pug template engine SSTI
- `ejs_ssti`: EJS template engine SSTI
- `handlebars_ssti`: Handlebars template engine SSTI

### Python (`python`)
- `os_system`: os.system executions
- `subprocess`: subprocess module executions
- `jinja2_ssti`: Jinja2 template engine SSTI

### PHP (`php`)
- `exec_system`: system/exec/shell_exec/passthru/eval/preg_replace executions

### Java (`java`)
- `runtime_exec`: Runtime.exec and ProcessBuilder
- `freemarker_ssti`: Freemarker template engine SSTI
- `velocity_ssti`: Velocity template engine SSTI
- `thymeleaf_ssti`: Thymeleaf template engine SSTI

### .NET (`dotnet`)
- `process_start`: Process.Start executions

### Ruby (`ruby`)
- `kernel_system`: system/backticks/exec executions
- `erb_ssti`: ERB template engine SSTI

### Perl (`perl`)
- `system_backticks`: system/backticks/exec executions

### Go (`go`)
- `os_exec`: exec.Command executions

### JavaScript (`javascript`)
- Legacy executions using require and eval

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

- New payload categories or sinks
- Additional encoding methods or constraint handlers
- Bug fixes
- Performance improvements
- Documentation enhancements

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is provided for educational and authorized testing purposes only. The developers are not responsible for any misuse or damage caused by this program.
