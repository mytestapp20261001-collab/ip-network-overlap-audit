import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("ip_audit_tool", ROOT / "tool.py")
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)

class AuditTests(unittest.TestCase):
    def run_audit(self, *nets):
        return tool.audit({"networks": list(nets)})
    def codes(self, result):
        return [item["code"] for item in result["findings"]]
    def test_good(self):
        self.assertEqual(self.run_audit("10.0.0.0/24", "10.0.1.0/24")["status"], "pass")
    def test_equal(self):
        r = self.run_audit("::/0", "::/0")
        self.assertEqual(r["findings"][0]["relation"], "equal")
    def test_contains_both_orders(self):
        for values, relation in [(('10.0.0.0/8', '10.1.0.0/16'), 'left_contains_right'),
                                 (('10.1.0.0/16', '10.0.0.0/8'), 'right_contains_left')]:
            self.assertEqual(self.run_audit(*values)["findings"][0]["relation"], relation)
    def test_family_separation(self):
        self.assertEqual(self.run_audit("0.0.0.0/0", "::/0")["overlap_count"], 0)
    def test_ipv6_containment(self):
        self.assertEqual(self.run_audit("2001:db8::/32", "2001:db8:1::/48")["overlap_count"], 1)
    def test_host_bits(self):
        r = self.run_audit("192.0.2.7/24")
        self.assertEqual(r["networks"][0]["cidr"], "192.0.2.0/24")
        self.assertIn("host_bits_set", self.codes(r))
    def test_host_prefixes(self):
        self.assertEqual(self.run_audit("255.255.255.255/32", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128")["status"], "pass")
    def test_no_host_iteration(self):
        r = self.run_audit("::/0")
        self.assertEqual(r["networks"][0]["address_count"], 2 ** 128)
    def test_classification_endpoints_only(self):
        r = self.run_audit("127.0.0.1/32")
        self.assertTrue(r["networks"][0]["endpoint_classification"]["first"]["is_loopback"])
        self.assertIn("classification_python_version", r)
    def test_invalid_cidrs_findings(self):
        for value in ["1.2.3.4", "10.0.0.0/33", "::/129", "::/01", "010.0.0.0/8", "fe80::%eth0/64", "10.0.0.0/255.0.0.0", " 10.0.0.0/8"]:
            with self.subTest(value=value):
                self.assertEqual(self.codes(self.run_audit(value)), ["invalid_cidr"])
    def test_schema_errors(self):
        for data in [[], {}, {"networks": []}, {"networks": [True]}, {"networks": ["x" * 129]}, {"networks": ["::/0"], "extra": 1}]:
            self.assertEqual(tool.audit(data)["status"], "error")
    def test_count_boundary_and_truncation(self):
        r = self.run_audit(*(["::/0"] * 256))
        self.assertEqual(r["overlap_count"], 32640)
        self.assertEqual(len(r["findings"]), 500)
        self.assertTrue(r["findings_truncated"])
        self.assertEqual(self.run_audit(*(["::/0"] * 257))["status"], "error")
    def test_stable(self):
        self.assertEqual(self.run_audit("::1/128"), self.run_audit("::1/128"))
    def cli(self, raw, *args):
        return subprocess.run([sys.executable, str(ROOT / "tool.py"), *args], input=raw, text=True, capture_output=True)
    def test_cli_exit_codes(self):
        for raw, code in [('{"networks":["::/0"]}', 0), ('{"networks":["bad"]}', 1), ('{}', 2)]:
            r = self.cli(raw)
            self.assertEqual(r.returncode, code, r.stderr)
            json.loads(r.stdout)
    def test_cli_file_examples(self):
        for name, code in [("good", 0), ("bad", 1)]:
            self.assertEqual(self.cli("", "--input", str(ROOT / "examples" / (name + ".json"))).returncode, code)
    def test_cli_rejects_duplicate_nonfinite_invalid_unicode(self):
        for raw in ['{"networks":[],"networks":[]}', '{"networks":NaN}', '{']:
            self.assertEqual(self.cli(raw).returncode, 2)
    def test_cli_size(self):
        self.assertEqual(self.cli(" " * (tool.MAX_BYTES + 1)).returncode, 2)
    def test_errors_do_not_echo_input(self):
        secret = "private-secret-userinfo"
        r = self.cli("", "--unrecognized", secret)
        self.assertEqual(r.returncode, 2)
        self.assertNotIn(secret, r.stdout + r.stderr)
        r = self.run_audit(secret)
        self.assertNotIn(secret, json.dumps(r))

    def test_cli_exact_byte_boundary(self):
        valid = '{"networks":["::/0"]}'
        self.assertEqual(self.cli(valid + " " * (tool.MAX_BYTES - len(valid))).returncode, 0)
    def test_cli_invalid_utf8_and_deep_json(self):
        result = subprocess.run([sys.executable, str(ROOT / "tool.py")], input=b"\xff", capture_output=True)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(b"Traceback", result.stderr)
        self.assertEqual(self.cli("[" * 1500 + "]" * 1500).returncode, 2)
    def test_nonregular_input_file(self):
        result = self.cli("", "--input", str(ROOT))
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(str(ROOT), result.stdout + result.stderr)

if __name__ == "__main__":
    unittest.main()
