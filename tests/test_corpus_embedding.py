"""Tests for the payload corpus embedded in rcekit.py.

RCEKit advertises itself as a single standard-library Python file, but the corpus
used to live only in templates/payloads.json — so a lone rcekit.py refused to
run. It now carries a built-in copy as a fallback.

That fallback introduces the risk it is worth guarding: two copies of the corpus
that can drift. templates/payloads.json remains the source of truth, and these
tests fail if the embedded copy stops matching it.
"""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import rcekit

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "rcekit.py"
CORPUS = REPO_ROOT / "templates" / "payloads.json"
EMBED_TOOL = REPO_ROOT / "tools" / "embed_corpus.py"


def run(*args, cwd):
    return subprocess.run(
        [sys.executable, *args], cwd=str(cwd),
        capture_output=True, text=True, timeout=120,
    )


class EmbeddedCorpusSyncTestCase(unittest.TestCase):
    def test_embedded_corpus_parses(self):
        data = json.loads(rcekit.EMBEDDED_PAYLOAD_CORPUS)
        self.assertIn("payload_categories", data)
        self.assertIn("detection_payloads", data)

    def test_embedded_corpus_matches_the_source_of_truth(self):
        """Structural comparison, so reformatting the JSON is not a failure."""
        self.assertEqual(
            json.loads(rcekit.EMBEDDED_PAYLOAD_CORPUS),
            json.loads(CORPUS.read_text(encoding="utf-8")),
            "templates/payloads.json changed without re-running tools/embed_corpus.py",
        )

    def test_embed_tool_reports_up_to_date(self):
        result = run(str(EMBED_TOOL), "--check", cwd=REPO_ROOT)
        self.assertEqual(
            result.returncode, 0,
            f"tools/embed_corpus.py --check failed: {result.stdout}{result.stderr}",
        )

    def test_backslashes_survived_embedding(self):
        """The corpus carries Windows paths; a cooked literal would eat them."""
        data = json.loads(rcekit.EMBEDDED_PAYLOAD_CORPUS)
        blob = json.dumps(data)
        self.assertIn(r"C:\\Windows", blob)


class StandaloneScriptTestCase(unittest.TestCase):
    """The whole point: rcekit.py on its own, with no data files beside it."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        shutil.copy(SCRIPT, Path(self.tmp) / "rcekit.py")

    def test_doctor_passes_with_no_corpus_file(self):
        result = run("rcekit.py", "--doctor", cwd=self.tmp)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("built-in", result.stdout)
        self.assertIn("[doctor] OK", result.stdout)

    def test_fallback_is_announced(self):
        """Silently swapping the corpus would mislead anyone who edited theirs."""
        result = run("rcekit.py", "--doctor", cwd=self.tmp)
        self.assertIn("Using the built-in payload corpus", result.stdout)

    def test_generation_works_and_matches_the_repo_corpus(self):
        standalone = run("rcekit.py", "--detection-only", "--output", "out.txt", cwd=self.tmp)
        self.assertEqual(standalone.returncode, 0, standalone.stdout + standalone.stderr)
        standalone_count = len((Path(self.tmp) / "out.txt").read_text().splitlines())

        in_repo_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, in_repo_dir, ignore_errors=True)
        in_repo = run(str(SCRIPT), "--detection-only",
                      "--output", str(Path(in_repo_dir) / "out.txt"), cwd=REPO_ROOT)
        self.assertEqual(in_repo.returncode, 0, in_repo.stdout + in_repo.stderr)
        in_repo_count = len((Path(in_repo_dir) / "out.txt").read_text().splitlines())

        self.assertGreater(standalone_count, 0)
        self.assertEqual(
            standalone_count, in_repo_count,
            "a lone rcekit.py generates a different corpus than the repository checkout",
        )

    def test_corrupt_corpus_file_does_not_fall_back(self):
        """A truncated or tampered corpus must still hard-fail, not be papered over."""
        templates = Path(self.tmp) / "templates"
        templates.mkdir()
        (templates / "payloads.json").write_text("{ this is not json", encoding="utf-8")
        result = run("rcekit.py", "--detection-only", "--output", "out.txt", cwd=self.tmp)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("Payload corpus is not usable", result.stdout)
        self.assertNotIn("built-in", result.stdout)


class ExplicitTemplateFileTestCase(unittest.TestCase):
    def test_missing_explicit_template_file_still_fails(self):
        """--template-file is authoritative: it never silently becomes the built-in."""
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        result = run(str(SCRIPT), "--detection-only",
                     "--template-file", str(Path(tmp) / "nope.json"),
                     "--output", str(Path(tmp) / "out.txt"), cwd=REPO_ROOT)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("template file not found", result.stdout)


class RepositoryCheckoutTestCase(unittest.TestCase):
    def test_checkout_still_reads_the_json_file(self):
        """Contributors edit templates/payloads.json and see the effect at once."""
        generator = rcekit.RCEKit()
        self.assertFalse(generator.uses_embedded_corpus())
        self.assertEqual(generator.corpus_source, str(CORPUS))

    def test_no_fallback_notice_in_a_checkout(self):
        result = run(str(SCRIPT), "--doctor", cwd=REPO_ROOT)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("built-in", result.stdout)


if __name__ == "__main__":
    unittest.main()
