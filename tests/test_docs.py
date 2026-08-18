"""Documentation integrity tests.

The docs are split across README.md and docs/, which makes them easy to drift
apart: a renamed heading silently breaks a cross-link, and a new CLI flag lands
undocumented. These tests keep the published docs honest without any external
dependency.
"""

import html
import re
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import rcekit

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "rcekit.py"
README = REPO_ROOT / "README.md"
CHANGELOG = REPO_ROOT / "CHANGELOG.md"
DOCS_DIR = REPO_ROOT / "docs"

FENCE_RE = re.compile(r"^\s*```", re.MULTILINE)
LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)\s]+)\)")
HEADING_RE = re.compile(r"^(#{1,6})\s+(.*?)\s*$")
OPTION_RE = re.compile(r"--[A-Za-z][A-Za-z0-9-]*")
# Flag declarations as argparse prints them: two spaces, the flags, then a run of
# whitespace before the description. Reading only this leading segment keeps the
# prose inside each help string — which name planned, not existing, flags — out.
DECLARATION_RE = re.compile(r"^ {2}(-\S[^ ]*(?:[ ,][^ ]+)*?)(?: {2,}|$)")


def markdown_files():
    return [README, CHANGELOG] + sorted(DOCS_DIR.glob("*.md"))


def strip_code_fences(text):
    """Drop fenced blocks so sample output and payloads aren't parsed as markdown."""
    parts = FENCE_RE.split(text)
    return "".join(parts[::2])


def slugify(heading):
    """Reproduce GitHub's heading-anchor algorithm."""
    text = html.unescape(heading)
    text = re.sub(r"`([^`]*)`", r"\1", text)
    text = re.sub(r"[*_]", "", text)
    text = re.sub(r"[^\w\s-]", "", text.lower())
    return text.strip().replace(" ", "-")


def anchors_of(path):
    body = strip_code_fences(path.read_text(encoding="utf-8"))
    found = set()
    for line in body.splitlines():
        match = HEADING_RE.match(line)
        if match:
            found.add(slugify(match.group(2)))
    return found


def links_of(path):
    body = strip_code_fences(path.read_text(encoding="utf-8"))
    return LINK_RE.findall(body)


class VersionBadgeTestCase(unittest.TestCase):
    def test_readme_badge_matches_dunder_version(self):
        """A stale badge misreports which release a reader is looking at."""
        text = README.read_text(encoding="utf-8")
        match = re.search(r"\*\*Version\s+(\d+\.\d+\.\d+)\*\*", text)
        self.assertIsNotNone(match, "README has no '**Version X.Y.Z**' badge")
        self.assertEqual(
            match.group(1),
            rcekit.__version__,
            "README version badge is out of sync with rcekit.__version__",
        )


class ChangelogTestCase(unittest.TestCase):
    """A release with no changelog entry is a release nobody can read."""

    RELEASE_RE = re.compile(r"^## \[(\d+\.\d+\.\d+)\]", re.MULTILINE)

    @classmethod
    def setUpClass(cls):
        cls.text = CHANGELOG.read_text(encoding="utf-8")

    def test_has_an_unreleased_section(self):
        self.assertIn("## [Unreleased]", self.text)

    def test_latest_entry_matches_dunder_version(self):
        releases = self.RELEASE_RE.findall(self.text)
        self.assertTrue(releases, "CHANGELOG.md documents no released version")
        self.assertEqual(
            releases[0], rcekit.__version__,
            "the newest CHANGELOG entry does not match rcekit.__version__ — "
            "every version bump needs an entry",
        )

    def test_releases_are_in_descending_order(self):
        releases = [tuple(int(p) for p in v.split(".")) for v in self.RELEASE_RE.findall(self.text)]
        self.assertEqual(releases, sorted(releases, reverse=True),
                         "CHANGELOG entries are not newest-first")

    def test_every_release_has_a_link_definition(self):
        defined = set(re.findall(r"^\[(\d+\.\d+\.\d+)\]:", self.text, re.MULTILINE))
        missing = sorted(set(self.RELEASE_RE.findall(self.text)) - defined)
        self.assertEqual(missing, [], f"versions with no link definition: {missing}")


class DocLinkTestCase(unittest.TestCase):
    def test_relative_links_resolve(self):
        broken = []
        for path in markdown_files():
            for target in links_of(path):
                if target.startswith(("http://", "https://", "mailto:", "#")):
                    continue
                relative = target.split("#", 1)[0]
                if not relative:
                    continue
                if not (path.parent / relative).exists():
                    broken.append(f"{path.name} -> {target}")
        self.assertEqual(broken, [], f"broken relative links: {broken}")

    def test_anchors_resolve(self):
        broken = []
        for path in markdown_files():
            for target in links_of(path):
                if target.startswith(("http://", "https://", "mailto:")):
                    continue
                if "#" not in target:
                    continue
                relative, anchor = target.split("#", 1)
                if not anchor:
                    continue
                destination = path if not relative else path.parent / relative
                if destination.suffix != ".md" or not destination.exists():
                    continue
                if anchor not in anchors_of(destination):
                    broken.append(f"{path.name} -> {target}")
        self.assertEqual(broken, [], f"links to missing headings: {broken}")

    def test_readme_points_at_every_doc_page(self):
        """A docs page nothing links to is a page nobody finds."""
        linked = {
            target.split("#", 1)[0]
            for target in links_of(README)
            if target.startswith("docs/")
        }
        for page in sorted(DOCS_DIR.glob("*.md")):
            self.assertIn(
                f"docs/{page.name}", linked, f"README does not link to docs/{page.name}"
            )


class ComparisonSectionTestCase(unittest.TestCase):
    """The comparison names other people's tools, so it has to stay checkable."""

    # Every project the section is allowed to name, and where a reader verifies it.
    PROJECTS = {
        "commix": "github.com/commixproject/commix",
        "SSTImap": "github.com/vladko312/SSTImap",
        "tplmap": "github.com/epinna/tplmap",
        "Nuclei": "github.com/projectdiscovery/nuclei",
        "interactsh": "github.com/projectdiscovery/interactsh",
        "sqlmap": "github.com/sqlmapproject/sqlmap",
    }

    @classmethod
    def setUpClass(cls):
        text = README.read_text(encoding="utf-8")
        start = text.find("## How RCEKit compares")
        assert start != -1, "README has no 'How RCEKit compares' section"
        end = text.find("\n## ", start + 1)
        cls.section = text[start:end if end != -1 else len(text)]

    def test_section_has_substance(self):
        self.assertGreater(len(self.section.splitlines()), 30)

    def test_named_projects_are_linked(self):
        """A claim about someone else's tool must ship with a way to check it."""
        unlinked = [
            name for name, url in self.PROJECTS.items()
            if name.lower() in self.section.lower() and url not in self.section
        ]
        self.assertEqual(
            unlinked, [], f"named in the comparison without a link to the project: {unlinked}"
        )

    def test_no_unvetted_project_is_named(self):
        """Adding a rival to the table means adding it here — and linking it."""
        for rival in ("metasploit", "burp suite", "acunetix", "tplmap2"):
            self.assertNotIn(
                rival, self.section.lower(),
                f"'{rival}' appears in the comparison but is not in PROJECTS",
            )


class CLIDocumentationTestCase(unittest.TestCase):
    """Guard against the CLI and its reference page drifting apart."""

    @classmethod
    def setUpClass(cls):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--help"],
            cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=120,
        )
        assert result.returncode == 0, result.stderr
        options = set()
        for line in result.stdout.splitlines():
            declaration = DECLARATION_RE.match(line)
            if declaration:
                options.update(OPTION_RE.findall(declaration.group(1)))
        cls.cli_options = options - {"--help"}
        cls.reference_text = (DOCS_DIR / "reference.md").read_text(encoding="utf-8")

    def test_help_output_was_parsed(self):
        # A guard on the test itself: if argparse ever changes its help layout,
        # the two tests below would silently pass on an empty set.
        self.assertGreater(len(self.cli_options), 30)
        self.assertIn("--verify-url", self.cli_options)
        self.assertIn("--request-file", self.cli_options)

    def test_every_cli_option_is_documented(self):
        undocumented = sorted(
            option for option in self.cli_options
            if not re.search(rf"`{re.escape(option)}`", self.reference_text)
        )
        self.assertEqual(
            undocumented, [], f"flags missing from docs/reference.md: {undocumented}"
        )

    def test_reference_documents_no_phantom_options(self):
        # Only flags written as code, so heading anchors like `#safety--consent`
        # aren't mistaken for a documented `--consent`.
        documented = set(re.findall(r"`(--[A-Za-z][A-Za-z0-9-]*)`", self.reference_text))
        phantom = sorted(documented - self.cli_options)
        self.assertEqual(
            phantom, [], f"docs/reference.md documents non-existent flags: {phantom}"
        )


if __name__ == "__main__":
    unittest.main()
