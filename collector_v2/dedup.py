"""Identity contract for de-duplication (collector_v2).

Two share links are merged ONLY if every connection-relevant field is identical after
these normalizations, and nothing else:
  * remark / name (URI #fragment, vmess "ps", "v", "remark") is ignored;
  * hostname is lower-cased; percent-encoding is decoded; query-parameter order is ignored;
  * hy2:// == hysteria2://, wg:// == wireguard://, socks5:// == socks://.
Everything else is part of the key: protocol, host, port, credentials (uuid/password/keys),
transport type, path, Host header, serviceName, security, SNI, ALPN (order kept), uTLS
fingerprint (raw value, not the parser's fallback), REALITY pbk/sid/spx, flow, encryption,
insecure flags, obfs, plugins and any other unknown query parameter.
The key is a SHA-256 digest, so secrets never appear in keys, logs or artifacts.
"""
import hashlib
import json
from urllib.parse import parse_qsl, unquote, urlsplit

from parsers import b64decode

ALIASES = {"hy2": "hysteria2", "wg": "wireguard", "socks5": "socks"}
SUPPORTED = {"vless", "vmess", "trojan", "ss", "hysteria2", "tuic", "anytls", "wireguard", "socks"}
VMESS_COSMETIC = {"ps", "v", "remark", "remarks"}


def _canonical(uri: str) -> dict:
    uri = uri.strip()
    scheme, _, rest = uri.partition("://")
    scheme = ALIASES.get(scheme.lower(), scheme.lower())
    if scheme == "vmess":
        d = json.loads(b64decode(rest.split("#", 1)[0]))
        d = {k: str(v).strip() for k, v in d.items() if k not in VMESS_COSMETIC}
        if "add" in d:
            d["add"] = d["add"].lower()
        return {"s": scheme, "d": d}
    p = urlsplit(f"{scheme}://{rest}")
    userinfo = unquote(p.netloc.rsplit("@", 1)[0]) if "@" in p.netloc else ""
    if scheme == "ss" and userinfo and ":" not in userinfo:
        try:
            userinfo = b64decode(userinfo)
        except Exception:
            pass
    if scheme == "ss" and not userinfo:  # ss://base64(method:pass@host:port)
        try:
            inner = b64decode(p.netloc)
            userinfo, _, hostport = inner.rpartition("@")
            p = urlsplit(f"ss://x@{hostport}?{p.query}")
        except Exception:
            pass
    q = sorted((k, unquote(v)) for k, v in parse_qsl(p.query, keep_blank_values=True))
    return {"s": scheme, "h": (p.hostname or "").lower(), "p": p.port, "u": userinfo,
            "path": unquote(p.path.rstrip("/")) if scheme != "ss" else "", "q": q}


def identity_key(uri: str) -> str | None:
    try:
        c = _canonical(uri)
    except Exception:
        return None
    if c["s"] not in SUPPORTED or (c["s"] != "vmess" and not (c.get("h") and c.get("p"))):
        return None
    return hashlib.sha256(json.dumps(c, sort_keys=True).encode()).hexdigest()


def dedupe(uris: list[str]) -> tuple[list[str], int]:
    """Keep first occurrence per identity key. Returns (unique, dropped_count). Invalid links dropped."""
    seen, out, dropped = set(), [], 0
    for u in uris:
        k = identity_key(u)
        if k is None or k in seen:
            dropped += 1
            continue
        seen.add(k)
        out.append(u)
    return out, dropped
