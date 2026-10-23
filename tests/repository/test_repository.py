"""Offline repository guards. These are regression checks, not a YAML policy engine."""

import ast
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "contracts/ilm-2.19.0"


class RepositoryChecks(unittest.TestCase):
    def test_catalog(self):
        catalog = json.loads((ROOT / "tests/catalog.json").read_text(encoding="utf-8"))
        self.assertEqual(catalog["schemaVersion"], 1)
        cases = catalog["cases"]
        self.assertTrue(cases)
        identifiers = [case["id"] for case in cases]
        self.assertEqual(len(identifiers), len(set(identifiers)))
        self.assertEqual({case["phase"] for case in cases}, {"P0", "P1", "P2", "P3", "P4"})
        for case in cases:
            with self.subTest(case=case["id"]):
                self.assertRegex(case["id"], r"^[RCDSTALP]-\d{3}$")
                self.assertIn(case["risk"], {"medium", "high", "critical"})
                self.assertIn(case["status"], {"implemented", "planned"})
                self.assertTrue(case["suite"].strip())
                for field in ("given", "when", "then"):
                    self.assertGreater(len(case[field].strip()), 5, field)
                if case["status"] == "planned":
                    self.assertNotIn("test", case, "Planned acceptance must not masquerade as executed")
                    continue
                relative, name = case["test"].split("::")
                path = (ROOT / relative).resolve()
                self.assertTrue(path.is_relative_to(ROOT))
                self.assertTrue(path.is_file(), relative)
                source = path.read_text(encoding="utf-8")
                if path.suffix == ".py":
                    names = {node.name for node in ast.walk(ast.parse(source)) if isinstance(node, ast.FunctionDef)}
                    self.assertIn(name, names)
                else:
                    self.assertRegex(source, rf"func {re.escape(name)}\(t \*testing\.T\)")

    def test_pinned_sources(self):
        manifest = json.loads((CONTRACT / "sources.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["commit"], "e62233777518296f70a151cf766dde5e1a6cea2d")
        declared = set()
        for entry in manifest["files"]:
            path = (CONTRACT / entry["path"]).resolve()
            self.assertTrue(path.is_relative_to(CONTRACT.resolve()))
            content = path.read_bytes()
            self.assertEqual(hashlib.sha256(content).hexdigest(), entry["sha256"], entry["path"])
            header = f"blob {len(content)}\0".encode("ascii")
            self.assertEqual(hashlib.sha1(header + content).hexdigest(), entry["gitBlob"], entry["path"])
            declared.add(path)
        self.assertEqual(declared, {path.resolve() for path in (CONTRACT / "java").glob("*.java")})

        # Independent source extraction: @RequestMapping base plus method mapping.
        extracted = {}
        for name in ("InfoController.java", "HealthController.java", "EntityController.java", "LocationController.java"):
            source = (CONTRACT / "java" / name).read_text(encoding="utf-8")
            base = re.search(r'@RequestMapping\("([^\"]+)"\)', source).group(1)
            mappings = list(re.finditer(r"@(Get|Post|Put|Delete)Mapping\s*\((.*?)\)", source, re.S))
            for index, match in enumerate(mappings):
                suffix_match = re.search(r'path\s*=\s*"([^\"]+)"', match.group(2))
                suffix = suffix_match.group(1) if suffix_match else ""
                tail = source[match.end():mappings[index + 1].start() if index + 1 < len(mappings) else len(source)]
                status = 204 if "@ResponseStatus(HttpStatus.NO_CONTENT)" in tail else 200
                extracted[(match.group(1).upper(), base + suffix)] = (name, status)
        routes = json.loads((CONTRACT / "routes.json").read_text(encoding="utf-8"))["routes"]
        expected = {(route["method"], route["path"]): (route["source"], route["status"]) for route in routes}
        self.assertEqual(len(routes), len(expected))
        self.assertEqual(extracted, expected)

    def test_workflow_boundaries(self):
        paths = sorted((ROOT / ".github/workflows").glob("*.yml"))
        self.assertEqual([path.name for path in paths], ["ci.yml"], "Review new workflows and their trust boundary")
        source = paths[0].read_text(encoding="utf-8")
        for forbidden in ("pull_request_target", "workflow_run", "repository_dispatch", "self-hosted", "secrets.", "secrets[", "id-token:", "packages:", "environment:"):
            self.assertNotIn(forbidden, source)
        self.assertNotRegex(source, r"\bwrite\b|\bwrite-all\b")
        self.assertRegex(source, r"(?m)^permissions:\n  contents: read\n")
        self.assertNotRegex(source, r"(?m)^ +permissions:")
        runners = re.findall(r"(?m)^ +runs-on: (.+)$", source)
        self.assertEqual(runners, ["ubuntu-24.04"] * 3)
        checkout_count = 0
        for action, revision in re.findall(r"(?m)^ +(?:- )?uses: ([^@\s]+)@([^\s#]+)", source):
            self.assertRegex(revision, r"^[0-9a-f]{40}$", action)
            if action == "actions/checkout":
                checkout_count += 1
        self.assertEqual(checkout_count, 3)
        self.assertEqual(source.count("persist-credentials: false"), checkout_count)
        self.assertIn("retention-days: 7", source)
        self.assertIn("path: artifacts/go-tests.json", source)
        self.assertNotRegex(source, r"(?i)@(?:main|master|latest)\b|continue-on-error:\s*true")

    def test_public_fixtures(self):
        private_key = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE" + r" KEY-----")
        token = re.compile(r"(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})")
        excluded = {".git", "__pycache__", "artifacts", "bin", "dist"}
        for path in ROOT.rglob("*"):
            if not path.is_file() or excluded.intersection(path.relative_to(ROOT).parts):
                continue
            relative = path.relative_to(ROOT)
            self.assertNotIn(relative.parts[0], {"local", "lab-results"})
            self.assertNotIn(path.suffix.lower(), {".pem", ".key", ".p12", ".pfx", ".sqlite", ".db"})
            self.assertNotRegex(path.name, r"^\.env(?:\.|$)")
            text = path.read_text(encoding="utf-8")
            self.assertIsNone(private_key.search(text), str(relative))
            self.assertIsNone(token.search(text), str(relative))
            if relative.parts[:2] == ("tests", "fixtures") and path.suffix != ".md":
                for value in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
                    address = ipaddress.ip_address(value)
                    allowed = any(address in ipaddress.ip_network(network) for network in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))
                    self.assertTrue(allowed, f"Non-documentation fixture address: {relative}")


if __name__ == "__main__":
    unittest.main()
