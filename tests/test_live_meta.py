import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import live_meta


class LiveMeta(unittest.TestCase):


    def test_release_source_is_canonical_android_repository(self):
        self.assertEqual(live_meta.APP_REPO, "hidooch980/molidovpn-android")

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

    def test_canonical_android_assets_keep_legacy_names_for_old_clients(self):
        source = [
            {"name": "MolidoMeshAI-android-arm64.apk", "size": 10,
             "browser_download_url": "https://github.com/new/release/arm64.apk",
             "digest": "sha256:" + "b" * 64},
            {"name": "MolidoMeshAI-android-armv7.apk", "size": 11,
             "browser_download_url": "https://github.com/new/release/armv7.apk",
             "digest": "sha256:" + "c" * 64},
            {"name": "MolidoMeshAI-android-universal.apk", "size": 12,
             "browser_download_url": "https://github.com/new/release/universal.apk",
             "digest": "sha256:" + "d" * 64},
        ]
        release = live_meta.release_body({"tag_name": "v4.0.2", "body": "", "assets": source})
        by_name = {a["name"]: a for a in release["assets"]}
        for suffix in ("arm64", "armv7", "universal"):
            canonical = by_name[f"MolidoMeshAI-android-{suffix}.apk"]
            for prefix in ("MolidoVPN", "MobinVPN"):
                alias = by_name[f"{prefix}-android-{suffix}.apk"]
                self.assertEqual(alias["browser_download_url"], canonical["browser_download_url"])
                self.assertEqual(alias["sha256"], canonical["sha256"])

    def test_unknown_flags_are_not_published(self):
        parts, files = live_meta.build({}, None, None, None)
        self.assertEqual(parts["flags"], "")
        self.assertNotIn("flags.json", files)


if __name__ == '__main__':
    unittest.main()
