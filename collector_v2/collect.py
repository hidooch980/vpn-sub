"""collector_v2 entry point: fetch allowlisted public sources, parse, dedupe, write artifacts.

No network scanning, no external APIs, no publishing. Output goes to OUT_DIR only.
Only aggregate counts are printed - never URIs, UUIDs or passwords.
"""
import collections
import json
import os
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from parsers import extract_configs, parse_uri  # noqa: E402
from collector_v2.dedup import ALIASES, dedupe  # noqa: E402
from collector_v2.sources import fetchable, load_allowlist, propose_candidates  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.environ.get("OUT_DIR", "collector_v2_out")
MAX_BYTES = 8 * 1024 * 1024
TIMEOUT = 20


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "molido-collector-v2"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return r.read(MAX_BYTES).decode("utf-8", errors="ignore")


def run(allowlist: str, discover: str | None = None) -> dict:
    sources = load_allowlist(allowlist)
    stats = {"run_utc": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()), "sources": {}}
    all_uris, origin_flags = [], {}
    for s in fetchable(sources):
        entry = {"status": s.status, "owner": s.owner}
        try:
            uris = [u for u in extract_configs(fetch(s.url)) if parse_uri(u)]
            entry["parsed"] = len(uris)
            all_uris += uris
        except Exception as e:
            entry["error"] = type(e).__name__
        stats["sources"][s.url] = entry
        origin_flags[s.url] = s.status
    unique, dropped = dedupe(all_uris)
    protos = collections.Counter(ALIASES.get(p, p) for p in (u.split("://", 1)[0].lower() for u in unique))
    stats.update(total_parsed=len(all_uris), unique=len(unique), duplicates_dropped=dropped,
                 protocols=dict(protos.most_common()), country="not measured in v2 phase 1-2 (see report)")
    candidates = []
    if discover and os.path.exists(discover):
        with open(discover, encoding="utf-8") as f:
            candidates = propose_candidates([l.strip() for l in f if l.strip() and not l.startswith("#")], sources)
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(f"{OUT_DIR}/unique_configs.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(unique) + ("\n" if unique else ""))
    with open(f"{OUT_DIR}/stats.json", "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=1)
    with open(f"{OUT_DIR}/candidates_for_review.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(candidates) + ("\n" if candidates else ""))
    return stats


if __name__ == "__main__":
    st = run(os.path.join(HERE, "sources_allowlist.txt"), os.path.join(os.path.dirname(HERE), "discover.txt"))
    print(json.dumps({k: v for k, v in st.items() if k != "sources"}, indent=1))
    print(f"sources fetched: {len(st['sources'])}, errors: {sum('error' in v for v in st['sources'].values())}")
