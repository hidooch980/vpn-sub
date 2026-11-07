"""Reviewed source allowlist. Auto-discovery may only *propose* candidates; it never promotes."""
from dataclasses import dataclass

FETCH_STATUSES = {"approved", "unverified_origin"}
VALID_STATUSES = FETCH_STATUSES | {"candidate", "rejected"}


@dataclass(frozen=True)
class Source:
    url: str
    owner: str
    review_date: str
    status: str
    notes: str = ""


def load_allowlist(path: str) -> list[Source]:
    out, seen = [], set()
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split("|")]
            if len(parts) < 4:
                raise ValueError(f"line {n}: expected url | owner | review_date | status | notes")
            url, owner, date, status = parts[:4]
            if status not in VALID_STATUSES:
                raise ValueError(f"line {n}: bad status {status!r}")
            if not url.startswith("https://"):
                raise ValueError(f"line {n}: only https sources allowed")
            if url in seen:
                raise ValueError(f"line {n}: duplicate url")
            seen.add(url)
            out.append(Source(url, owner, date, status, parts[4] if len(parts) > 4 else ""))
    return out


def fetchable(sources: list[Source]) -> list[Source]:
    return [s for s in sources if s.status in FETCH_STATUSES]


def propose_candidates(discovered: list[str], sources: list[Source]) -> list[str]:
    """Return new URLs for human review. Never changes status of anything."""
    known = {s.url for s in sources}
    return [u for u in dict.fromkeys(discovered) if u.startswith("https://") and u not in known]
