#!/usr/bin/env python3
"""Offline tests for the hacking-vault tools.

Every test calls the real tool code in-process with fixed inputs and asserts
what it must produce. No network, no external binaries, no shared temp files:
each test that writes stays inside its own TemporaryDirectory, so the suite runs
alone or beside others and on any OS. Run: python3 -m unittest -v (from repo root).
"""

import base64
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(ROOT))


def load(path, name):
    """Import a standalone script by file path (names contain hyphens)."""
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


jwt = load(SCRIPTS / "crypto" / "jwt-tool.py", "jwt_tool")
cipher = load(SCRIPTS / "crypto" / "classic-cipher.py", "classic_cipher")
encode = load(SCRIPTS / "crypto" / "encode.py", "encode_tool")
fileinspect = load(SCRIPTS / "forensics" / "fileinspect.py", "fileinspect")
hashcrack = load(SCRIPTS / "crypto" / "hashcrack.py", "hashcrack")


def make_hs256(payload, secret, alg="HS256"):
    """Build a real HS* token so the crack/verify paths get a true positive."""
    header = {"alg": alg, "typ": "JWT"}
    h = jwt.b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = jwt.b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = jwt.hs_sign(f"{h}.{p}".encode(), secret.encode(), alg)
    return f"{h}.{p}.{jwt.b64url_encode(sig)}", header


class JwtTest(unittest.TestCase):
    """JWT weaknesses are a protection path; a false negative lets a bad token through."""

    def test_crack_hs256_finds_weak_secret(self):
        token, header = make_hs256({"user": "guest", "admin": False}, "s3cr3t")
        parts = token.split(".")
        with tempfile.TemporaryDirectory() as d:
            wl = Path(d) / "words.txt"
            wl.write_text("wrong\nalso-wrong\ns3cr3t\nlater\n", encoding="utf-8")
            found = jwt.crack_hs(parts, header, str(wl))
        # Red if hs_sign/compare drift apart or the loop stops early: no match.
        self.assertEqual(found, "s3cr3t")

    def test_crack_returns_none_when_absent(self):
        token, header = make_hs256({"user": "guest"}, "s3cr3t")
        parts = token.split(".")
        with tempfile.TemporaryDirectory() as d:
            wl = Path(d) / "words.txt"
            wl.write_text("a\nb\nc\n", encoding="utf-8")
            self.assertIsNone(jwt.crack_hs(parts, header, str(wl)))

    def test_alg_none_is_flagged(self):
        notes = jwt.warnings({"alg": "none"})
        # Red if the alg:none check is dropped: the warning disappears.
        self.assertTrue(any("alg=none" in n for n in notes))

    def test_forge_none_keeps_payload_and_strips_signature(self):
        token, _ = make_hs256({"user": "guest"}, "s3cr3t")
        parts = token.split(".")
        forged = jwt.forge_none(parts)
        fp = forged.split(".")
        self.assertEqual(len(fp), 3)
        self.assertEqual(fp[1], parts[1])          # payload preserved
        self.assertEqual(fp[2], "")                # empty signature
        self.assertEqual(json.loads(jwt.b64url_decode(fp[0]))["alg"], "none")


class ClassicCipherTest(unittest.TestCase):

    def test_caesar_round_trip_and_scoring(self):
        plain = "flag{hello_world} the quick brown fox"
        ct = cipher.caesar_shift(plain, 3)
        self.assertEqual(cipher.caesar_shift(ct, 23), plain)   # 23 = -3 mod 26
        # The scorer must rank real plaintext above the shifted gibberish,
        # or the `all` ranking is worthless.
        self.assertGreater(cipher.plaintext_score(plain.encode()),
                           cipher.plaintext_score(ct.encode()))

    def test_atbash_is_its_own_inverse(self):
        self.assertEqual(cipher.atbash(cipher.atbash("Hello, World")), "Hello, World")

    def test_single_byte_xor_round_trip(self):
        data = b"flag{xor_me}"
        self.assertEqual(cipher.xor_bytes(cipher.xor_bytes(data, b"\x42"), b"\x42"), data)

    def test_railfence_known_vector(self):
        # "HELLO" over 2 rails encrypts to "HLOEL"; decrypt must recover it.
        self.assertEqual(cipher.railfence_decrypt("HLOEL", 2), "HELLO")


class EncodeTest(unittest.TestCase):

    def test_all_order_covers_every_codec(self):
        # `all` is the headline feature; a codec missing from ALL_ORDER would
        # silently never appear in the all-at-once output.
        self.assertEqual(set(encode.ALL_ORDER), set(encode.CODECS))

    def test_base64_matches_stdlib(self):
        self.assertEqual(encode.CODECS["base64"](b"secret"),
                         base64.b64encode(b"secret").decode())

    def test_rot13_is_involution(self):
        once = encode._rot(b"Attack", 13)
        self.assertEqual(encode._rot(once.encode(), 13), "Attack")


class FileInspectTest(unittest.TestCase):

    def test_identify_from_magic_bytes(self):
        png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16
        self.assertEqual(fileinspect.identify(png), "PNG image")
        self.assertEqual(fileinspect.identify(b"nothing here"), "unknown / raw data")

    def test_entropy_bounds(self):
        self.assertEqual(fileinspect.entropy(b"\x00" * 256), 0.0)
        self.assertAlmostEqual(fileinspect.entropy(bytes(range(256))), 8.0, places=6)

    def test_carves_appended_zip(self):
        # A ZIP glued past the end of a PNG is the classic stego trick.
        host = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
        blob = host + b"PK\x03\x04" + b"\x00" * 8
        hits = fileinspect.find_embedded(blob)
        self.assertIn((len(host), "ZIP archive"), hits)
        # The host's own leading PNG magic at offset 0 must not be reported.
        self.assertFalse(any(off == 0 for off, _ in hits))

    def test_strings_extracts_flag(self):
        data = b"\x00\x01flag{found_me}\xff\xfe"
        found = [s for _, s in fileinspect.extract_strings(data, 4)]
        self.assertIn("flag{found_me}", found)


class CipherFormFlagsTest(unittest.TestCase):
    """The menu/web form sends crypto.cipher flags (--brute/--hex/--key) with any
    subcommand. Each must be accepted, or the form produces a 'rc 2' argparse
    error. Exercises the real CLI so the parent-parser wiring is covered."""

    SCRIPT = str(SCRIPTS / "crypto" / "classic-cipher.py")

    def _run(self, *args):
        return subprocess.run([sys.executable, self.SCRIPT, *args],
                              capture_output=True, text=True,
                              stdin=subprocess.DEVNULL)

    def test_shared_flags_accepted_by_every_subcommand(self):
        # 'rc == 2' is argparse's "unrecognized arguments": the bug this guards.
        for cmd in ("all", "caesar", "xor", "atbash", "railfence", "freq"):
            r = self._run(cmd, "khoor", "--brute")
            self.assertNotEqual(r.returncode, 2,
                                f"{cmd} rejected --brute: {r.stderr}")

    def test_hex_is_honoured_outside_xor(self):
        # 6b686f6f72 = 'khoor'; caesar must decode the hex, not choke on --hex.
        r = self._run("caesar", "6b686f6f72", "--hex")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("khoor", r.stdout)

    def test_vigenere_without_key_fails_cleanly(self):
        r = self._run("vigenere", "rijvs")
        self.assertEqual(r.returncode, 1)
        self.assertNotIn("Traceback", r.stderr)


class HashCrackTest(unittest.TestCase):
    """Cracking is a protection-relevant path; a miss on a present word is a real bug."""

    def test_cracks_md5_from_wordlist(self):
        target = hashlib.md5(b"banana").hexdigest()
        with tempfile.TemporaryDirectory() as d:
            wl = Path(d) / "w.txt"
            wl.write_text("apple\ncherry\nbanana\ngrape\n", encoding="utf-8")
            words = hashcrack.load_words(str(wl))
        pw, algo = hashcrack.crack(target, words, hashcrack.candidates(target))
        # Red if the loop stops early or the encoding drifts: banana is missed.
        self.assertEqual((pw, algo), ("banana", "md5"))

    def test_sha256_detected_by_length(self):
        target = hashlib.sha256(b"flag").hexdigest()
        self.assertIn("sha256", hashcrack.candidates(target))
        pw, algo = hashcrack.crack(target, ["x", "flag", "y"],
                                   hashcrack.candidates(target))
        self.assertEqual((pw, algo), ("flag", "sha256"))

    def test_absent_word_returns_none(self):
        target = hashlib.sha1(b"absent").hexdigest()
        pw, _ = hashcrack.crack(target, ["a", "b", "c"],
                                hashcrack.candidates(target))
        self.assertIsNone(pw)


class ReportTest(unittest.TestCase):
    """report.generate chains tools through runner.run; stub the runner so the
    test stays offline and asserts the chaining and the written file, not a scan."""

    def setUp(self):
        from hvault import report, runner
        from hvault.spec import build_registry
        self.report = report
        self.registry = build_registry()
        self._real_run = runner.run
        runner.run = lambda spec, values, timeout=0: (0, f"STUB::{spec.id}")
        self._tmp = tempfile.TemporaryDirectory()
        self._real_reports = report.REPORTS
        report.REPORTS = Path(self._tmp.name)

    def tearDown(self):
        from hvault import runner
        runner.run = self._real_run
        self.report.REPORTS = self._real_reports
        self._tmp.cleanup()

    def test_domain_report_runs_only_passive_osint(self):
        out = self.report.generate(self.registry, "example.com")
        text = out.read_text(encoding="utf-8")
        for tool_id in ("osint.footprint", "osint.crtsh", "osint.wayback"):
            self.assertIn(f"STUB::{tool_id}", text)
        # Passive sweep must not reach for any active (Recon/Web) tool.
        self.assertNotIn("STUB::recon.portscan", text)
        self.assertNotIn("STUB::recon.dnsrecon", text)
        self.assertNotIn("STUB::web.dirscan", text)
        # username-hunt needs a username, not a domain: it must stay out.
        self.assertNotIn("STUB::osint.username", text)

    def test_active_flag_adds_recon_and_web(self):
        out = self.report.generate(self.registry, "example.com", active=True)
        text = out.read_text(encoding="utf-8")
        for tool_id in ("recon.dnsrecon", "recon.portscan", "recon.httpprobe",
                        "recon.webenum", "web.dirscan", "web.cors"):
            self.assertIn(f"STUB::{tool_id}", text)
        # The heavy vulnscan orchestrator is deliberately excluded.
        self.assertNotIn("STUB::scan.vulnscan", text)

    def test_only_category_runs_just_that_category(self):
        out = self.report.generate(self.registry, "example.com", only="recon")
        text = out.read_text(encoding="utf-8")
        # --only names an active category, so it runs without --active...
        self.assertIn("STUB::recon.dnsrecon", text)
        # ...and nothing from another category leaks in.
        self.assertNotIn("STUB::osint.crtsh", text)
        self.assertNotIn("STUB::web.dirscan", text)

    def test_unknown_only_category_is_rejected(self):
        with self.assertRaises(ValueError) as cm:
            self.report.generate(self.registry, "example.com", only="nope")
        self.assertIn("unknown category", str(cm.exception))

    def test_ip_without_active_is_rejected(self):
        with self.assertRaises(ValueError) as cm:
            self.report.generate(self.registry, "203.0.113.5")
        self.assertIn("--active", str(cm.exception))

    def test_ip_with_active_scans_it(self):
        out = self.report.generate(self.registry, "203.0.113.5", active=True)
        text = out.read_text(encoding="utf-8")
        self.assertIn("STUB::recon.portscan", text)
        # No domain-only tool should be attempted against a bare IP.
        self.assertNotIn("STUB::recon.dnsrecon", text)
        self.assertNotIn("STUB::osint.crtsh", text)

    def test_garbage_target_is_rejected(self):
        with self.assertRaises(ValueError):
            self.report.generate(self.registry, "not a target")


if __name__ == "__main__":
    unittest.main()
