import base64, json, os, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from collector_v2.dedup import dedupe, identity_key
from collector_v2.sources import fetchable, load_allowlist, propose_candidates

U = "11111111-2222-3333-4444-555555555555"
BASE = f"vless://{U}@1.2.3.4:443?security=tls&type=ws&path=%2Fa&host=h.example&sni=s.example&alpn=h2,http/1.1&fp=chrome"
REAL = f"vless://{U}@1.2.3.4:443?security=reality&sni=www.google.com&fp=chrome&pbk=KEY1&sid=ab&flow=xtls-rprx-vision"


def vm(**kw):
    d = {"v": "2", "ps": "x", "add": "ex.com", "port": "443", "id": U, "net": "ws", "path": "/p", "tls": "tls"}
    d.update(kw)
    return "vmess://" + base64.b64encode(json.dumps(d).encode()).decode()


class Dedup(unittest.TestCase):
    def same(self, a, b): self.assertEqual(identity_key(a), identity_key(b))
    def diff(self, a, b): self.assertNotEqual(identity_key(a), identity_key(b))

    def test_remark_ignored(self): self.same(BASE + "#one", BASE + "#two")
    def test_param_order_and_host_case(self):
        self.same(BASE, f"vless://{U}@1.2.3.4:443?fp=chrome&alpn=h2,http/1.1&sni=s.example&host=h.example&path=/a&type=ws&security=tls")
        self.same("trojan://pw@EX.com:443?sni=a", "trojan://pw@ex.com:443?sni=a")
    def test_alias(self): self.same("hy2://pw@h:443?sni=a", "hysteria2://pw@h:443?sni=a")
    def test_vmess_remark(self): self.same(vm(ps="a"), vm(ps="b"))
    def test_transport(self): self.diff(BASE, BASE.replace("type=ws", "type=grpc"))
    def test_path(self): self.diff(BASE, BASE.replace("%2Fa", "%2Fb"))
    def test_host_header(self): self.diff(BASE, BASE.replace("host=h.example", "host=h2.example"))
    def test_sni(self): self.diff(BASE, BASE.replace("sni=s.example", "sni=t.example"))
    def test_alpn(self): self.diff(BASE, BASE.replace("alpn=h2,http/1.1", "alpn=h2"))
    def test_fingerprint(self): self.diff(BASE, BASE.replace("fp=chrome", "fp=firefox"))
    def test_unknown_fp_not_collapsed(self):  # parser maps unknown fp to chrome; dedup must not
        self.diff(BASE, BASE.replace("fp=chrome", "fp=weird"))
    def test_reality_pbk(self): self.diff(REAL, REAL.replace("KEY1", "KEY2"))
    def test_reality_sid(self): self.diff(REAL, REAL.replace("sid=ab", "sid=cd"))
    def test_credential(self): self.diff(BASE, BASE.replace(U, U[:-1] + "6"))
    def test_password(self): self.diff("trojan://pw1@h:443", "trojan://pw2@h:443")
    def test_port(self): self.diff(BASE, BASE.replace(":443", ":8443"))
    def test_vmess_fields(self):
        self.diff(vm(), vm(path="/q")); self.diff(vm(), vm(sni="x")); self.diff(vm(), vm(id=U[:-1] + "9"))
    def test_ss_forms(self):
        a = "ss://" + base64.b64encode(b"aes-256-gcm:pw").decode() + "@h:8388#a"
        self.same(a, "ss://aes-256-gcm:pw@h:8388#b")
        self.diff(a, "ss://aes-256-gcm:pw2@h:8388")
    def test_key_has_no_secret(self):
        k = identity_key(BASE)
        self.assertNotIn(U, k); self.assertEqual(len(k), 64)
    def test_dedupe(self):
        out, dropped = dedupe([BASE + "#1", BASE + "#2", BASE.replace("fp=chrome", "fp=ios"), "garbage"])
        self.assertEqual(len(out), 2); self.assertEqual(dropped, 2)


class Allowlist(unittest.TestCase):
    def test_real_allowlist(self):
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        src = load_allowlist(os.path.join(here, "sources_allowlist.txt"))
        prod = [l.strip() for l in open(os.path.join(os.path.dirname(here), "sources.txt"))
                if l.strip() and not l.startswith("#")]
        self.assertEqual({s.url for s in fetchable(src)}, set(prod))  # nothing removed
        wd = [s for s in src if "workers.dev" in s.url]
        self.assertEqual(len(wd), 2)
        self.assertTrue(all(s.status == "unverified_origin" for s in wd))

    def test_candidates_never_promoted(self):
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as f:
            f.write("https://a/x | o | 2026-11-07 | approved |\nhttps://c/y | o | 2026-11-07 | candidate |\n")
        src = load_allowlist(f.name)
        self.assertEqual([s.url for s in fetchable(src)], ["https://a/x"])
        self.assertEqual(propose_candidates(["https://a/x", "https://n/z", "http://insecure"], src), ["https://n/z"])
        self.assertEqual([s.status for s in load_allowlist(f.name)], ["approved", "candidate"])

    def test_bad_status_rejected(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write("https://a | o | d | promoted |\n")
        with self.assertRaises(ValueError):
            load_allowlist(f.name)


if __name__ == "__main__":
    unittest.main()
