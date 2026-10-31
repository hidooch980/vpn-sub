"""Live meta: the small files apps check for changes, on the `live` branch of this repo.

Apps read `version.json` from GitHub (raw, then jsDelivr) on foreground, network change, connect
and every ~10 min while open, and download a file only when its hash in `version.json` changed.
The Cloudflare Worker is read once per run here (`/app/live.json`), never by the apps for this.

Output (directory given as argv[1]):
  version.json  {"v", "flags", "notice", "release", "critical", "resilience", "catalog", "at"}
  flags.json    notice.json    latest.json (GitHub "latest release" shape, + sha256 and critical)
"""
import hashlib
import json
import os
import sys
import time
import urllib.request

WORKER = "https://molido-sub.hidooch980.workers.dev"
APP_REPO = "hidooch980/molidovpn"
RESILIENCE = "https://raw.githubusercontent.com/hidooch980/molidovpn-android/main/remote/resilience.json"
SUB_UPDATED = "https://raw.githubusercontent.com/hidooch980/vpn-sub/sub/meta/updated"
LIVE_RAW = "https://raw.githubusercontent.com/hidooch980/vpn-sub/live/"


def get(url, headers=None, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": "molido-live", **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8")


def h(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def dumps(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def latest_release(token):
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    r = json.loads(get(f"https://api.github.com/repos/{APP_REPO}/releases/latest", headers))
    return release_body(r)


def release_body(r):
    def asset(a):
        d = a.get("digest") or ""
        out = {"name": a["name"], "size": a.get("size"), "browser_download_url": a["browser_download_url"]}
        if d.startswith("sha256:") and len(d) == 71:
            out["digest"] = d
            out["sha256"] = d[7:]
        return out
    return {
        "tag_name": r["tag_name"],
        "published_at": r.get("published_at"),
        "critical": "[critical]" in (r.get("body") or "").lower(),
        "assets": [asset(a) for a in r.get("assets", [])],
    }


def build(live, release, resilience, catalog, previous=None):
    """Files to publish. Same inputs -> same version, so an unchanged run publishes nothing."""
    # Unknown (Worker down, nothing published yet): no file and an empty hash, so apps keep theirs.
    flags = dumps(live["flags"]) if isinstance(live.get("flags"), dict) else None
    notice = dumps(live["notice"]) if isinstance(live.get("notice"), dict) else None
    latest = dumps(release) if release else (previous or {}).get("latest.json")
    rel = release or {}
    parts = {
        "flags": h(flags) if flags else "",
        "notice": h(notice) if notice else "",
        "release": rel.get("tag_name") or (previous or {}).get("release") or "",
        "critical": bool(rel.get("critical")),
        "resilience": h(resilience) if resilience else "",
        "catalog": (catalog or "").strip(),
    }
    parts["v"] = h(dumps(parts))
    files = {k: v for k, v in (("flags.json", flags), ("notice.json", notice)) if v}
    if latest:
        files["latest.json"] = latest
    return parts, files


def main(out):
    token = os.environ.get("GH_TOKEN", "")
    prev = {}
    try:
        prev = json.loads(get(LIVE_RAW + "version.json"))
    except Exception:
        pass
    live = None
    try:
        live = json.loads(get(WORKER + "/app/live.json"))
    except Exception as e:
        print("worker:", e)
    if live is None:  # Worker down or over quota: keep the published copies.
        try:
            live = {"flags": json.loads(get(LIVE_RAW + "flags.json")), "notice": json.loads(get(LIVE_RAW + "notice.json"))}
        except Exception:
            live = {}
    try:
        release = latest_release(token)
    except Exception as e:
        print("release:", e)
        release = None
    resilience = None
    try:
        resilience = get(RESILIENCE)
    except Exception:
        pass
    catalog = None
    try:
        catalog = get(SUB_UPDATED)
    except Exception:
        pass
    parts, files = build(live, release, resilience, catalog)
    os.makedirs(out, exist_ok=True)
    for name, body in files.items():
        with open(os.path.join(out, name), "w", encoding="utf-8") as f:
            f.write(body)
    version = dict(parts, at=int(time.time()))
    with open(os.path.join(out, "version.json"), "w") as f:
        f.write(dumps(version))
    changed = prev.get("v") != parts["v"]
    print("version", parts, "changed" if changed else "unchanged")
    with open(os.environ.get("GITHUB_OUTPUT", os.devnull), "a") as f:
        f.write(f"changed={'true' if changed else 'false'}\nversion={parts['v']}\n")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "live")
