"""No VMware calls: strict native-state classification and no fence guessing."""
import unittest
from pathlib import Path
import subprocess
import sys
from scripts.m08_vix_state import decode_power


class StateTests(unittest.TestCase):
    def test_only_known_consistent_steady_states_are_admissible(self):
        for flags, running, error, expected in ((8, 1, 0, "powered_on"),
                (72, 1, 0, "powered_on"), (2, 0, 0, "powered_off"),
                (2, 1, 0, "unknown"), (8, 0, 0, "unknown"),
                (66, 0, 0, "unknown"), (2 | 0x400, 0, 0, "unknown"),
                (8 | 0x4000, 1, 0, "unknown"), (2, 0, 7, "unknown"),
                (8 | 0x200, 1, 0, "transition_or_uncertain"),
                (2 | 1, 0, 0, "transition_or_uncertain")):
            with self.subTest(flags=flags, running=running, error=error):
                self.assertEqual(decode_power(flags, running, error), expected)

    def test_optimized_host_cannot_bypass_assertion_based_checks(self):
        for code in ("from acp.vmware_host import VMwareHost; VMwareHost(None)",
                     "from scripts.m08_vmware_validate import Validation; Validation()",
                     "from scripts.m08_vmware_validate import ProcessWitness; ProcessWitness(None)"):
            with self.subTest(entry=code):
                result = subprocess.run([sys.executable, "-O", "-B", "-c", code],
                    cwd=Path(__file__).resolve().parents[1], capture_output=True, timeout=15)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b"Optimized host Python is unsupported", result.stderr)
