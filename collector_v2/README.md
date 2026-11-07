# collector_v2 (experimental, manual only)

- `sources_allowlist.txt`: reviewed sources (`url | owner | review_date | status | notes`). Only `approved` and `unverified_origin` are fetched. `candidate` entries are proposals for a human to review and are never promoted automatically. Production `sources.txt` stays as it is.
- The two `workers.dev` sources are marked `unverified_origin`: the owner isn't documented. That label makes no claim about abuse.
- `dedup.py`: the exact identity contract is in its docstring. Only the remark/name, query order, host case and scheme aliases are normalized. Any difference in transport, path, Host, SNI, ALPN, fingerprint, REALITY, credential or port keeps both configs. The key is a SHA-256 hash, so no secret is ever logged.
- `collect.py`: fetches, parses and dedupes, then writes `unique_configs.txt`, `stats.json` and `candidates_for_review.txt` to `OUT_DIR`. It prints aggregate counts only.
- Workflow `.github/workflows/collector-v2.yml`: `workflow_dispatch` only, artifact output, no schedule, no publishing.

Tests: `python -m unittest discover -s collector_v2/tests -t .`
