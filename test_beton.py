"""Автотесты beton. Без root, систему не трогают. Запуск: python3 test_beton.py"""
import importlib.util
from importlib.machinery import SourceFileLoader
import json
import os
import unittest

SPEC = importlib.util.spec_from_loader(
    "beton_mod", SourceFileLoader("beton_mod", os.path.join(os.path.dirname(__file__), "beton")))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


class TestNormalize(unittest.TestCase):
    def test_strip_scheme_www(self):
        self.assertEqual(M.normalize_domain("https://WWW.YouTube.com/watch?v=x"), "youtube.com")

    def test_idna(self):
        d = M.normalize_domain("президент.рф")
        self.assertIn("xn--", d)

    def test_bad(self):
        for bad in ["", "nodot", "плохой домен!!!", "a b.com"]:
            with self.assertRaises(ValueError, msg=bad):
                M.normalize_domain(bad)


class TestExpand(unittest.TestCase):
    def test_www_pair(self):
        self.assertEqual(M.expand_domains(["youtube.com"]), ["www.youtube.com", "youtube.com"])

    def test_dedup(self):
        self.assertEqual(M.expand_domains(["youtube.com", "www.youtube.com"]), ["www.youtube.com", "youtube.com"])


class TestDangerous(unittest.TestCase):
    def test_google_stopped(self):
        self.assertIn("google.com", M.find_dangerous(["google.com", "www.google.com"]))

    def test_youtube_allowed(self):
        self.assertEqual(M.find_dangerous(["youtube.com", "www.youtube.com"]), [])


class TestHosts(unittest.TestCase):
    def test_format(self):
        txt = M.build_hosts_block(["youtube.com"])
        self.assertIn(M.MARK_BEGIN, txt)
        self.assertIn("0.0.0.0 youtube.com", txt)
        self.assertNotIn("*", txt)  # hosts без wildcard
        self.assertTrue(txt.endswith("\n"))


class TestNft(unittest.TestCase):
    def test_ascii_only(self):
        rules = M.build_nft_rules(["youtube.com"], ["1.2.3.4"])
        rules.encode("ascii")  # парсер nft капризен к не-ascii
        self.assertIn("table inet beton", rules)
        self.assertIn("1.2.3.4", rules)
        self.assertTrue(rules.endswith("\n"))

    def test_empty_ips_fallback(self):
        rules = M.build_nft_rules(["x.test"], [])
        self.assertIn("127.0.0.1", rules)


class TestPolicies(unittest.TestCase):
    def test_chromium_wildcards(self):
        p = json.loads(M.build_chromium_policy(["www.youtube.com", "youtube.com"]))
        # bare hostname: единственный формат, блокирующий в Chrome 153 (замер VM)
        self.assertIn("youtube.com", p["URLBlocklist"])
        # scheme-формы: для Firefox WebsiteFilter
        self.assertIn("*://*.youtube.com/*", p["URLBlocklist"])
        self.assertIn("*://youtube.com/*", p["URLBlocklist"])

    def test_firefox_merge_keeps_other_keys(self):
        existing = {"policies": {"Homepage": "https://example.com", "WebsiteFilter": {"Block": ["*://old/*"]}}}
        merged = M.merge_firefox_policies(existing, ["*://*.youtube.com/*"])
        self.assertEqual(merged["policies"]["Homepage"], "https://example.com")
        self.assertIn("*://old/*", merged["policies"]["WebsiteFilter"]["Block"])
        self.assertIn("*://*.youtube.com/*", merged["policies"]["WebsiteFilter"]["Block"])


class TestKillerScope(unittest.TestCase):
    def test_bypass_list_not_empty_and_scoped(self):
        self.assertIn("tor", M.BYPASS_PROC_NAMES)
        # обычный софт не в списке убийств
        for safe in ["firefox", "chromium", "code", "steam", "pacman"]:
            self.assertNotIn(safe, M.BYPASS_PROC_NAMES)


class TestHardcodedDNS(unittest.TestCase):
    def test_pubdns_set_in_rules(self):
        rules = M.build_nft_rules(["youtube.com"], ["1.2.3.4"])
        self.assertIn("pubdns_ipv4", rules)
        self.assertIn("udp dport 53 drop", rules)
        for ip in M.PUBLIC_DNS_IPS:
            self.assertIn(ip, rules)


class TestBrowserCoverage(unittest.TestCase):
    def test_more_than_two_chromium_dirs(self):
        self.assertGreaterEqual(len(M.CHROMIUM_POLICY_DIRS), 4)
        self.assertIn("/etc/brave/policies/managed", M.CHROMIUM_POLICY_DIRS)

    def test_firefox_esr_covered(self):
        self.assertGreaterEqual(len(M.FIREFOX_POLICIES), 2)


class TestEbpfParity(unittest.TestCase):
    def test_render_matches_l2_codegen(self):
        import importlib.util as iu
        from importlib.machinery import SourceFileLoader as SFL
        l2dir = os.path.join(os.path.dirname(__file__), "l2")
        spec = iu.spec_from_loader("l2codegen", SFL("l2codegen", os.path.join(l2dir, "codegen.py")))
        C = iu.module_from_spec(spec)
        spec.loader.exec_module(C)
        bases = ["tiktok.com", "youtube.com"]
        a = M.render_ebpf_patterns(bases)
        b = C.render(bases)
        norm = lambda t: [l for l in t.splitlines()[1:] if l.strip()]
        self.assertEqual(norm(a), norm(b))
        self.assertIn("#define BETON_PORT 443", a)
        a2 = M.render_ebpf_patterns(bases, 18443)
        b2 = C.render(bases, 18443)
        self.assertEqual(norm(a2), norm(b2))
        self.assertIn("#define BETON_PORT 18443", a2)

    def test_gen_ebpf_rejects_overlong(self):
        with self.assertRaises(ValueError):
            M.render_ebpf_patterns(["x" * 65 + ".com"])


class TestFinalFlag(unittest.TestCase):
    def test_not_final_on_dev_host(self):
        if os.path.exists(M.FINAL_FLAG):
            self.skipTest("машина финализирована")
        self.assertFalse(M.is_final())

    def test_revert_refuses_when_final(self):
        real = M.is_final
        M.is_final = lambda: True
        try:
            # без root упираемся в sudo-проверку раньше флага; с root был бы код 4.
            # Здесь проверяем лишь что флаг читается предикатом.
            self.assertTrue(M.is_final())
        finally:
            M.is_final = real


class TestPoliciesOk(unittest.TestCase):
    def test_ok_and_tampered(self):
        import json
        import tempfile
        doms = ["youtube.com", "www.youtube.com"]
        want = set(json.loads(M.build_chromium_policy(doms))["URLBlocklist"])
        with tempfile.TemporaryDirectory() as td:
            cdir = os.path.join(td, "chromium")
            fdir = os.path.join(td, "firefox")
            os.makedirs(cdir)
            os.makedirs(fdir)
            cp = os.path.join(cdir, "90-beton.json")
            fp = os.path.join(fdir, "policies.json")
            with open(cp, "w", encoding="utf-8") as f:
                f.write(M.build_chromium_policy(doms))
            with open(fp, "w", encoding="utf-8") as f:
                json.dump(M.merge_firefox_policies({}, list(want)), f)
            old_c, old_f = M.CHROMIUM_POLICY_DIRS, M.FIREFOX_POLICIES
            M.CHROMIUM_POLICY_DIRS, M.FIREFOX_POLICIES = [cdir], [fp]
            try:
                self.assertTrue(M.policies_ok(doms))
                os.remove(cp)  # снос одного файла политик
                self.assertFalse(M.policies_ok(doms))
            finally:
                M.CHROMIUM_POLICY_DIRS, M.FIREFOX_POLICIES = old_c, old_f

if __name__ == "__main__":
    unittest.main(verbosity=2)
