"""Тесты гейта L3. Без root. Запуск: python3 test_gate.py"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
import gate


class TestGate(unittest.TestCase):
    def test_bare_metal_refused(self):
        ok, msg = gate.check_vm("none")
        self.assertFalse(ok)

    def test_vm_types_accepted(self):
        for v in ["qemu", "kvm", "virtualbox"]:
            ok, _ = gate.check_vm(v)
            self.assertTrue(ok, v)

    def test_allow_requires_phrase(self):
        with mock.patch("builtins.open", mock.mock_open(read_data="мусор")):
            ok, _ = gate.check_allow()
            self.assertFalse(ok)
        with mock.patch("builtins.open", mock.mock_open(read_data="Я ПРИНИМАЮ НЕОБРАТИМОСТЬ 2026-09-13")):
            ok, _ = gate.check_allow()
            self.assertTrue(ok)

    def test_run_all_shape(self):
        res = gate.run_all()
        self.assertEqual([n for n, _, _ in res], ["root", "vm", "uefi-setup", "allow", "matrix", "state"])
        self.assertTrue(all(isinstance(ok, bool) for _, ok, _ in res))

    def test_setup_mode_parsing(self):
        with mock.patch.object(gate, "read_efivar", side_effect=[1, 0]):
            ok, msg = gate.check_uefi_setup()
            self.assertTrue(ok)
            self.assertIn("Setup Mode", msg)
        with mock.patch.object(gate, "read_efivar", side_effect=[0, 1]):
            ok, _ = gate.check_uefi_setup()
            self.assertTrue(ok)
        with mock.patch.object(gate, "read_efivar", side_effect=[0, 0]):
            ok, _ = gate.check_uefi_setup()
            self.assertFalse(ok)

    def test_host_fails_gate(self):
        # На хосте-разработке (bare metal, без ALLOW-файлов) гейт обязан краснеть.
        self.assertNotEqual(gate.main(), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
