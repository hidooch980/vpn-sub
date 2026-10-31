import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import live_meta


class LiveMeta(unittest.TestCase):


    def test_same_inputs_same_version_and_changes_move_it(self):
        live = {"flags": {"disabled": [], "default_mode": "auto"}, "notice": {}}
        rel = {"tag_name": "v3.2.1", "critical": False, "assets": []}
        a, files = live_meta.build(live, rel, "{}", "123")
        b, _ = live_meta.build(live, rel, "{}", "123")
        assert a == b
        assert set(files) == {"flags.json", "notice.json", "latest.json"}
        c, _ = live_meta.build({**live, "flags": {"disabled": ["tor"], "default_mode": "auto"}}, rel, "{}", "123")
        assert c["v"] != a["v"] and c["flags"] != a["flags"] and c["notice"] == a["notice"]
        d, _ = live_meta.build(live, {**rel, "tag_name": "v3.2.2"}, "{}", "123")
        assert d["release"] == "v3.2.2" and d["v"] != a["v"]


    def test_release_body_marks_critical_and_sha(self):
        r = live_meta.release_body({
            "tag_name": "v1", "body": "fix [CRITICAL] leak",
            "assets": [{"name": "MolidoVPN-android-arm64.apk", "size": 3, "browser_download_url": "https://x/a",
                        "digest": "sha256:" + "a" * 64}],
        })
        assert r["critical"] is True
        assert r["assets"][0]["sha256"] == "a" * 64
        assert live_meta.release_body({"tag_name": "v2", "body": "", "assets": []})["critical"] is False

    def test_unknown_flags_are_not_published(self):
        parts, files = live_meta.build({}, None, None, None)
        self.assertEqual(parts["flags"], "")
        self.assertNotIn("flags.json", files)


if __name__ == '__main__':
    unittest.main()
