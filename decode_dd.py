#!/usr/bin/env python3
"""decode_dd.py - universal decoder for blockchain dead-drop resolver payloads.

Malware ("etherhiding") stores its C2 config in public smart contracts and
reads it via read-only JSON-RPC eth_call. This tool either pulls the stored
value live (POST eth_call to a public RPC) or decodes an already-captured
result hex offline, then attempts every known encoding layer in order:

  1. ABI-encoded dynamic string/bytes (0x20 offset + length header)
  2. raw hex -> UTF-8
  3. base64
  4. gzip+base64 (JADESNOW/merlion style)
  5. base64+XOR: single-byte brute force and 16-byte repeating-key
     per-position printable-ratio heuristic (CLEARFAKE style)
  6. nested encoded blobs are recursed, depth max 3

All decoded content is attacker-controlled DATA: only string operations are
performed, nothing is ever executed. Decode with errors='replace' throughout.

stdlib only, Python 3.10+.

CLI:
  python3 decode_dd.py --chain polygon --to 0x<40hex> [--data 0x<8hex>]
  python3 decode_dd.py --rpc https://... --to 0x<40hex> --data 0x<8hex>
  python3 decode_dd.py --chain eth --to 0x<40hex> --data 0x<8hex> --block 25678470
  python3 decode_dd.py --chain eth --to 0x<40hex> --data 0x<8hex> --at-time 1754...
  python3 decode_dd.py --chain polygon --resolve-time 1792147844934
  python3 decode_dd.py --hex 0x...   (offline: decode a raw result)

Importable API:
  decode_hex(hexstr) -> dict
  pull_and_decode(rpc_url, to_addr, selector, block="latest") -> dict
  resolve_block_by_timestamp(rpc_url, ts) -> (block_number, block_timestamp, error)
"""

from __future__ import annotations

import argparse
import base64
import binascii
import gzip
import json
import re
import sys
import time
import urllib.error
import urllib.request

__version__ = "1.1.0"

MAX_DEPTH = 3
DEFAULT_TIMEOUT = 20
RPC_RETRIES = 2
# conservative public-RPC pacing between calls from the same process
RPC_PAUSE = 0.2

CHAIN_PRESETS = {
    "eth": "https://ethereum.publicnode.com",
    "polygon": "https://polygon.publicnode.com",
    "bsc": "https://bsc-dataseed.binance.org",
    "base": "https://mainnet.base.org",
}

# plain curl-like UA; some public RPCs reject python-urllib
USER_AGENT = "curl/8.5.0"

# ---------------------------------------------------------------------------
# indicators / verdict
# ---------------------------------------------------------------------------

URL_RE = re.compile(r"https?://[^\s\"'<>\\)\]}\x00-\x1f]{4,}", re.I)
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,14}\b", re.I)
# EVM contract/wallet addresses (dispatcher dead-drops resolve to these)
ADDR_RE = re.compile(r"\b0x[0-9a-fA-F]{40}\b")

COMMON_TLDS = {
    "com", "net", "org", "io", "st", "xyz", "top", "ru", "su", "cc", "pw",
    "info", "biz", "online", "site", "shop", "store", "live", "dev", "app",
    "me", "tv", "co", "us", "uk", "de", "nl", "in", "pro", "club", "fun",
    "space", "website", "link", "zone", "one", "vip", "icu", "cam", "cfd",
    "sbs", "monster", "wiki", "tech", "cloud", "click", "email", "world",
    "life", "win", "mob", "am", "to", "ly", "gg", "so", "tk", "ml", "ga",
    "cf", "gq", "cn", "kp", "id", "art", "bar", "bet", "bond", "cyou",
    "fit", "gel", "hub", "kit", "lol", "moe", "quest", "rest", "rink",
}

SCRIPT_INDICATORS = [
    "function ", "<script", "#!/", "require(", "curl ", "wget ",
    "recaptcha", "<!doctype", "<html",
    "| base64 -d", "base64 --decode", "base64 -D", "Invoke-Expression",
    "iex (", "powershell -", "cmd.exe /c", "bash -c", "sh -c",
    "/bin/sh", "/bin/bash", "eval(", "document.write", "atob(",
    "exec(mz", "mshta ", "rundll32 ", "certutil -urlcache",
]

SHELL_PREFIXES = ("#!/bin/", "#!/usr/bin/", " powershell", "$(")


def printable_ratio(data) -> float:
    """Fraction of bytes/chars that are printable ASCII or common whitespace."""
    if not data:
        return 0.0
    if isinstance(data, bytes):
        data = data.decode("utf-8", "replace")
    ok = sum(1 for c in data if c.isprintable() and ord(c) < 127 or c in "\r\n\t")
    return ok / len(data)


def empty_iocs() -> dict:
    return {"urls": [], "ips": [], "domains": [], "addresses": []}


def find_iocs(text: str) -> dict:
    """Extract URLs / IPs / domain tokens / EVM addresses from decoded text."""
    urls = sorted(set(m.group(0).rstrip(".,;:") for m in URL_RE.finditer(text)))
    ips = sorted(set(m.group(0) for m in IP_RE.finditer(text)))
    addresses = sorted(set(m.group(0).lower() for m in ADDR_RE.finditer(text)))
    domains = set()
    for m in DOMAIN_RE.finditer(text):
        tok = m.group(0).lower()
        tld = tok.rsplit(".", 1)[-1]
        # reject pure-numeric and hex-garbage tokens; require a known TLD
        if tld in COMMON_TLDS and not tok.replace(".", "").isdigit():
            if "." in tok[:-len(tld) - 1] or len(tok) > 4:  # require a label + tld
                domains.add(tok)
    domains -= {u.split("//")[-1].split("/")[0] for u in urls}
    return {"urls": urls, "ips": ips, "domains": sorted(domains),
            "addresses": addresses}


def has_iocs(iocs: dict) -> bool:
    return any(iocs.get(k) for k in ("urls", "ips", "domains", "addresses"))


def looks_malicious(text: str) -> bool:
    if has_iocs(find_iocs(text)):
        return True
    low = text.lower()
    if any(ind.lower() in low for ind in SCRIPT_INDICATORS):
        return True
    if any(low.rstrip().startswith(p.strip()) for p in SHELL_PREFIXES if p.startswith("#!")):
        return True
    return False


def verdict_for(texts: list[str]) -> tuple[str, dict]:
    """Scan all decoded variants; POSITIVE if any carries IOC/script content."""
    all_iocs = empty_iocs()
    for t in texts:
        for k, v in find_iocs(t).items():
            all_iocs[k] = sorted(set(all_iocs[k]) | set(v))
    positive = has_iocs(all_iocs)
    if not positive:
        low_all = "\n".join(texts).lower()
        positive = any(ind.lower() in low_all for ind in SCRIPT_INDICATORS)
    return ("POSITIVE" if positive else "NEGATIVE"), all_iocs


# ---------------------------------------------------------------------------
# decoding layers
# ---------------------------------------------------------------------------

def try_abi_string(raw: bytes):
    """Standard ABI dynamic string/bytes return: word0=offset(0x20), word1=len."""
    if len(raw) < 64:
        return None
    try:
        offset = int.from_bytes(raw[0:32], "big")
        if offset < 32 or offset > len(raw):
            return None
        o = offset
        if o + 32 > len(raw):
            return None
        length = int.from_bytes(raw[o:o + 32], "big")
        if length > (len(raw) - o - 32) or length == 0:
            return None
        data = raw[o + 32:o + 32 + length]
        return data.decode("utf-8", "replace")
    except (ValueError, OverflowError):
        return None


def try_abi_strings(raw: bytes) -> list[bytes]:
    """All plausible ABI dynamic string/byte payloads in a return blob.

    Tuple returns like getScript() -> (string, string, bool, uint256) carry
    several (offset, length) headers in the head words; single-string returns
    are the classic word0=0x20 case. Also returns the raw payload bytes for
    embedded-key XOR probing. Returns list of candidate byte strings."""
    n = len(raw)
    out, seen = [], set()
    for wpos in range(0, min(n, 32 * 8), 32):
        off = int.from_bytes(raw[wpos:wpos + 32], "big")
        if off < 32 or off % 32 or off + 32 > n:
            continue
        length = int.from_bytes(raw[off:off + 32], "big")
        if length == 0 or length > n - off - 32:
            continue
        data = raw[off + 32:off + 32 + length]
        if data in seen:
            continue
        seen.add(data)
        out.append(data)
    return out


def xor_embedded_key(data: bytes, min_ratio: float = 0.85):
    """Self-describing XOR blob (1-ether-wp style): byte0 = key length, then
    the repeating-XOR key, then the encrypted payload. If the decrypted
    payload again starts with a [len][key] header (nested C2-key header), the
    body after it is preferred. Returns {"key", "ratio", "text"} or None."""
    if len(data) < 8:
        return None
    kl = data[0]
    if not (1 <= kl <= 64) or 1 + kl + 2 > len(data):
        return None
    key = data[1:1 + kl]
    if not any(key):
        return None
    payload = data[1 + kl:]
    dec = bytes(b ^ key[i % kl] for i, b in enumerate(payload))
    text = None
    bkl = dec[0]
    if 1 <= bkl <= 64 and 1 + bkl < len(dec):
        body = dec[1 + bkl:]
        if printable_ratio(body) >= min_ratio:
            text = body.decode("utf-8", "replace")
    if text is None:
        if printable_ratio(dec) >= min_ratio:
            text = dec.decode("utf-8", "replace")
        else:
            return None
    return {"key": key.hex(), "ratio": round(printable_ratio(text), 3), "text": text}


def try_b64(text: str):
    """base64-decode text, tolerating whitespace/newlines. None if not b64.
    Tolerates delimiter wrappers around the core (CLEARFAKE stores
    ".." + base64(xored-js) + ".." on-chain)."""
    s = re.sub(r"\s+", "", text)
    s = s.strip(".")
    if len(s) < 8 or len(s) % 4 != 0:
        return None
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", s):
        return None
    try:
        out = base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None
    return out if out else None


def try_gunzip(data: bytes):
    if data[:2] == b"\x1f\x8b":
        try:
            return gzip.decompress(data)
        except (OSError, EOFError, ValueError):
            return None
    return None


def xor_single_brute(data: bytes, min_ratio: float = 0.9):
    """Single-byte XOR brute; return candidates above min printable ratio."""
    # short blobs are highly ambiguous (dozens of keys give near-100% printable
    # output), so report all qualifying candidates and let the verdict scan
    # check every text - a true hit must never be lost to ranking.
    out = []
    for k in range(256):
        if k == 0:
            continue  # identity variant is already reported by earlier layers
        dec = bytes(b ^ k for b in data)
        r = printable_ratio(dec)
        if r >= min_ratio:
            out.append({"key": k, "ratio": round(r, 3),
                        "text": dec.decode("utf-8", "replace")})
    out.sort(key=lambda c: (-c["ratio"], -_char_score(c["text"].encode())))
    return out[:32]


def _char_score(data: bytes) -> float:
    """Weighted text-likeness: whitespace > letters > digits > punct > printable."""
    s = 0.0
    for b in data:
        c = chr(b)
        if c in " \r\n\t":
            s += 2.0
        elif c.isalpha():
            s += 1.0
        elif c.isdigit():
            s += 0.8
        elif c in ".,:;/-":
            s += 0.5
        elif 32 <= b < 127:
            s += 0.2
    return s / max(1, len(data))


def xor_repeat16_heuristic(data: bytes, min_ratio: float = 0.85):
    """16-byte repeating-key heuristic: solve each key position independently
    for the byte that maximizes text-likeness across that column.
    Time-bounded (16*256 ops); flags CLEARFAKE-style b64+repeating-XOR.
    Needs >=48 bytes so each key-position column has enough samples."""
    if len(data) < 48:
        return None
    ks = bytearray(16)
    for pos in range(16):
        col = data[pos::16]
        best, best_s = 0, -1.0
        for k in range(256):
            dec = bytes(b ^ k for b in col)
            s = _char_score(dec)
            if s > best_s:
                best_s, best = s, k
        ks[pos] = best
    if not any(ks):
        return None  # zero key = no XOR, already covered
    dec = bytes(b ^ ks[i % 16] for i, b in enumerate(data))
    r = printable_ratio(dec)
    if r >= min_ratio:
        return {"key": bytes(ks).hex(), "ratio": round(r, 3),
                "text": dec.decode("utf-8", "replace")}
    return None


def xor_repeat_deep(data: bytes, klen: int = 16, max_ratio: float = 0.85,
                    beam_width: int = 200, tol: int = 4):
    """Deep repeating-XOR key recovery for cases the fast per-column heuristic
    leaves as high-printable gibberish.

    Per-column printable-count argmax cannot recover the key here: small
    per-column key deltas (<0x20) map attacker JS to other printable gibberish
    at ~100% printable ratio, so the column metric is ill-posed. What survives
    a small delta is never the token structure, so:

    1. per column keep every key byte whose printable-ASCII count is within
       `tol` of the column max (tiny candidate sets, true byte always in)
    2. beam-search the 16 columns jointly, scoring the incrementally decoded
       text by JS/script token hits (tokens couple columns; gibberish scores 0)
    3. token-scored coordinate ascent to fix residuals
    Accepts only text that is printable AND malicious-looking (IOC or script
    indicator), so wrong-key noise can never become a variant. stdlib only."""
    n = len(data)
    if n < klen * 8:
        return None

    def printable_ascii(b: int) -> bool:
        return 0x20 <= b < 0x7F or b in (9, 10, 13)

    # 1. per-column candidate key bytes
    cands = []
    for p in range(klen):
        col = data[p::klen]
        scores = [(sum(1 for b in col if printable_ascii(b ^ k)), k)
                  for k in range(256)]
        m = max(s for s, _ in scores)
        cands.append([k for s, k in sorted(scores, key=lambda x: -x[0])
                      if m - s <= tol])

    toks = ("var ", "if(", "function", "typeof", "return", "length",
            "window", "document", "script", "http", "eval(", "charAt",
            "curl ", "wget ", "require(")
    max_tok = max(len(t) for t in toks)

    # 2/3. EM loop: beam search over columns 0..klen-1 scoring the
    # incrementally decoded text by token hits, then a full-text token-scored
    # coordinate ascent; reseed the beam with the ascended key and repeat.
    # Single-coordinate ascent alone stalls when several adjacent columns are
    # wrong (no single move adds a token); the reseeded beam breaks that.
    def tok_score(key, limit):
        dec = bytes(b ^ key[i % klen] for i, b in enumerate(data[:limit]))
        t = dec.decode("utf-8", "replace").lower()
        return sum(t.count(w) for w in toks)

    seeds = [{}]
    best_key = None
    best_tok = 0
    for rnd in range(4):
        limit = 600 if rnd < 2 else min(n, 2000)
        states = []
        for sd in seeds[:4]:
            st = dict(sd)
            states.append(({"_seed": st}, "", 0, 0.0))
        for c in range(klen):
            p = c
            nxt = []
            for km, tail, tc, gc in states:
                forced = km.get("_seed", {}).get(p)
                ks = list(cands[p])
                if forced is not None and forced not in ks:
                    ks.append(forced)
                for k in ks:
                    b = data[c] ^ k
                    t2 = tail + chr(b) if 32 <= b < 127 else tail
                    if len(t2) > max_tok:
                        t2 = t2[-max_tok:]
                    tc2 = tc + (1 if any(t2.endswith(t) for t in toks) else 0)
                    gc2 = gc + (1 if printable_ascii(b) else 0)
                    nxt.append((km | {p: k}, t2, tc2, gc2))
            nxt.sort(key=lambda s: (-s[2], -s[3]))
            states = nxt[:beam_width]
        # coordinate-ascent each beam leader
        seeds = []
        for km, _, _, _ in states[:4]:
            key = [km.get(p, 0) for p in range(klen)]
            cur = tok_score(key, limit)
            for _ in range(3):
                moved = False
                for p in range(klen):
                    orig, bestk, bs = key[p], key[p], cur
                    for k in range(256):
                        key[p] = k
                        s = tok_score(key, limit)
                        if s > bs:
                            bs, bestk = s, k
                    key[p] = bestk
                    if bestk != orig:
                        cur = bs
                        moved = True
                if not moved:
                    break
            full_tok = tok_score(key, n)
            if full_tok > best_tok:
                best_tok, best_key = full_tok, bytes(key)
            seeds.append({p: key[p] for p in range(klen)})
        if best_key is not None and best_tok >= 20:
            break

    tried = [best_key] if best_key is not None else []

    best = None
    for key in tried:
        dec = bytes(b ^ key[i % klen] for i, b in enumerate(data))
        text = dec.decode("utf-8", "replace")
        if printable_ratio(text) < max_ratio or not looks_malicious(text):
            continue
        low = text.lower()
        toks_n = sum(low.count(w) for w in toks)
        if best is None or toks_n > best[0]:
            best = (toks_n, key, text)
    if best is None:
        return None
    _, key, text = best
    return {"key": key.hex(), "ratio": round(printable_ratio(text), 3),
            "text": text}


def _add_variant(variants, seen_texts, method, data_bytes):
    text = data_bytes.decode("utf-8", "replace")
    if not text.strip():
        return text
    r = printable_ratio(text)
    if r >= 0.85 or looks_malicious(text):
        key = (method, text)
        if key not in seen_texts:
            seen_texts.add(key)
            variants.append({"method": method, "text": text,
                             "printable_ratio": round(r, 3)})
    return text


def decode_hex(hexstr: str, depth: int = 0) -> dict:
    """Decode one raw eth_call result hex. Universal, offline. Returns dict:
    {raw_hex, state, variants: [{method, text, printable_ratio}], verdict, iocs}.
    Recurses into nested encoded blobs up to MAX_DEPTH."""
    hexstr = (hexstr or "").strip()
    if hexstr.lower() == "0x" or not hexstr:
        return {"raw_hex": "0x", "state": "burned/rotated", "variants": [],
                "verdict": "NEGATIVE", "iocs": empty_iocs()}
    h = hexstr[2:] if hexstr.lower().startswith("0x") else hexstr
    try:
        raw = bytes.fromhex(h)
    except ValueError:
        return {"raw_hex": hexstr[:80], "state": "invalid-hex", "variants": [],
                "verdict": "NEGATIVE", "iocs": empty_iocs()}

    variants: list[dict] = []
    seen: set = set()
    texts: list[str] = []

    # layer 1: ABI dynamic string/bytes (single string or multi-string tuple)
    abi_blobs = try_abi_strings(raw)
    base_layers = []
    for i, ab in enumerate(abi_blobs):
        nm = "abi-string" if len(abi_blobs) == 1 else "abi-string[%d]" % i
        base_layers.append((nm, ab.decode("utf-8", "replace")))
    # layer 2: raw utf-8
    raw_txt = raw.decode("utf-8", "replace")
    base_layers.append(("raw-utf8", raw_txt))

    for name, text in base_layers:
        texts.append(_add_variant(variants, seen, name, text.encode("utf-8", "replace")))

    # layer 1.5: self-describing embedded-key XOR blobs (raw + each ABI payload)
    for name, blob in [("raw", raw)] + [("abi-bytes[%d]" % i, ab)
                                        for i, ab in enumerate(abi_blobs)]:
        ek = xor_embedded_key(blob)
        if ek:
            texts.append(_add_variant(variants, seen,
                                      "%s+embedded-xor(key=%s)" % (name, ek["key"]),
                                      ek["text"].encode("utf-8", "replace")))

    # layers 3-5 applied to each base layer that is itself text
    for name, text in base_layers:
        blob = try_b64(text)
        if blob is None:
            continue
        # layer 3: base64
        texts.append(_add_variant(variants, seen, f"{name}+base64", blob))
        # layer 4: gzip+base64
        gz = try_gunzip(blob)
        if gz is not None:
            texts.append(_add_variant(variants, seen, f"{name}+base64+gzip", gz))
            blob2 = gz
        else:
            blob2 = blob
        # layer 1.5b: embedded-key XOR on the decoded blob
        ek = xor_embedded_key(blob2)
        if ek:
            texts.append(_add_variant(variants, seen,
                                      f"{name}+base64+embedded-xor(key={ek['key']})",
                                      ek["text"].encode("utf-8", "replace")))
        # layer 5: XOR on the base64-decoded (or gunzipped) content
        for cand in xor_single_brute(blob2):
            texts.append(_add_variant(variants, seen,
                                      f"{name}+base64+xor1(0x{cand['key']:02x})",
                                      cand["text"].encode("utf-8", "replace")))
        r16 = xor_repeat16_heuristic(blob2)
        # layer 5b: deep repeating-XOR recovery when the fast heuristic only
        # produces high-printable gibberish; its exact key supersedes the
        # heuristic variant (which is then not reported). Skipped when the
        # blob was gunzipped (already the final layer) or when any earlier
        # variant of this value is already verdict-bearing.
        deep = None
        if (len(blob2) >= 256 and gz is None
                and not any(looks_malicious(t) for t in texts)
                and (r16 is None or not looks_malicious(r16["text"]))):
            deep = xor_repeat_deep(blob2)
        if r16 and not deep:
            texts.append(_add_variant(variants, seen,
                                      f"{name}+base64+xor16(key={r16['key']})",
                                      r16["text"].encode("utf-8", "replace")))
        if deep:
            texts.append(_add_variant(variants, seen,
                                      f"{name}+base64+xor16deep(key={deep['key']})",
                                      deep["text"].encode("utf-8", "replace")))

    # also: raw gzip without base64
    gz = try_gunzip(raw)
    if gz is not None:
        texts.append(_add_variant(variants, seen, "raw-gzip", gz))

    # layer 6: recursion - a decoded layer that is itself an encoded blob
    if depth < MAX_DEPTH:
        for v in list(variants):
            t = v["text"].strip()
            nested = None
            if re.fullmatch(r"(0x)?[0-9a-fA-F]+", t) and len(t) >= 64:
                nested = decode_hex(t, depth + 1)
                nm = v["method"] + "->hex"
            else:
                b = try_b64(t)
                if b is not None and printable_ratio(b) > 0.85:
                    nested = decode_hex("0x" + b.hex(), depth + 1)
                    nm = v["method"] + "->base64"
            if nested and nested.get("variants"):
                for nv in nested["variants"]:
                    texts.append(_add_variant(variants, seen, nm + ":" + nv["method"],
                                              nv["text"].encode("utf-8", "replace")))

    verdict, iocs = verdict_for(texts)
    return {"raw_hex": "0x" + h, "state": "ok", "variants": variants,
            "verdict": verdict, "iocs": iocs}


# ---------------------------------------------------------------------------
# JSON-RPC pull (retry pattern scavenged from 13-slow-sky probe_rpc.py)
# ---------------------------------------------------------------------------

def rpc_call(url: str, method: str, params: list, timeout: int = DEFAULT_TIMEOUT):
    """POST one JSON-RPC call; returns (result_or_None, error_or_None)."""
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                       "params": params}).encode()
    last_err = None
    for attempt in range(RPC_RETRIES + 1):
        req = urllib.request.Request(url, data=body, headers={
            "User-Agent": USER_AGENT, "Content-Type": "application/json",
            "Accept": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                j = json.loads(r.read().decode("utf-8", "replace"))
            if j.get("error"):
                return None, str(j["error"])[:200]
            return j.get("result"), None
        except urllib.error.HTTPError as e:
            last_err = "HTTP %d: %s" % (e.code, e.read().decode("utf-8", "replace")[:120])
        except Exception as e:  # noqa: BLE001 - record and retry
            last_err = "EXC: %s" % e
        if attempt < RPC_RETRIES:
            time.sleep(1.0 + attempt)
    return None, last_err or "unknown error"


def eth_call(rpc_url: str, to_addr: str, selector: str,
             block: str = "latest") -> tuple[str | None, str | None]:
    """Read-only eth_call {"to":..., "data":...} at a block tag/number."""
    data = selector if selector.startswith("0x") else ("0x" + selector if selector else "")
    params = [{"to": to_addr, "data": data}, block or "latest"]
    return rpc_call(rpc_url, "eth_call", params)


def latest_block_number(rpc_url: str):
    """Current chain head as an int; (None, error) if the RPC can't answer."""
    blk, err = rpc_call(rpc_url, "eth_getBlockByNumber", ["latest", False])
    if err or not blk or "number" not in blk:
        return None, err or "no latest block"
    return int(blk["number"], 16), None


def normalize_block(block: str) -> str:
    """Accept decimal or 0x-hex block numbers; pass tags through."""
    if block is None:
        return "latest"
    b = str(block).strip()
    if b.lower() in ("latest", "earliest", "pending", "safe", "finalized"):
        return b.lower()
    return hex(int(b, 16) if b.lower().startswith("0x") else int(b, 10))


def resolve_block_by_timestamp(rpc_url: str, ts: int | str):
    """Find the highest block whose timestamp is <= ts.

    ts may be epoch seconds or milliseconds. Returns
    (block_number, block_timestamp, error).
    """
    try:
        ts = int(ts)
    except (TypeError, ValueError):
        return None, None, "not an integer timestamp"
    if ts > 10**12:  # milliseconds -> seconds
        ts //= 1000
    latest, err = rpc_call(rpc_url, "eth_getBlockByNumber", ["latest", False])
    if err or not latest:
        return None, None, err or "no latest block"
    hi = int(latest["number"], 16)
    latest_ts = int(latest["timestamp"], 16)
    if ts >= latest_ts:
        return hi, latest_ts, None
    lo = 0
    while lo < hi:
        mid = (lo + hi + 1) // 2
        blk, e = rpc_call(rpc_url, "eth_getBlockByNumber", [hex(mid), False])
        if e or not blk:
            return None, None, "block %d: %s" % (mid, e)
        if int(blk["timestamp"], 16) <= ts:
            lo = mid
        else:
            hi = mid - 1
        time.sleep(RPC_PAUSE)
    blk, e = rpc_call(rpc_url, "eth_getBlockByNumber", [hex(lo), False])
    if e or not blk:
        return None, None, e or "no block at %d" % lo
    return lo, int(blk["timestamp"], 16), None


def pull_and_decode(rpc: str, to_addr: str, selector: str,
                    block: str = "latest", block_ts: int | None = None,
                    latest_block: int | None = None) -> dict:
    """Pull the dead-drop value over read-only eth_call and decode it.
    Returns decode dict + {rpc, to, selector, block, block_timestamp,
    latest_block}. latest_block is best-effort context only."""
    out = {"rpc": rpc, "to": to_addr, "selector": selector,
           "block": block or "latest", "block_timestamp": block_ts,
           "latest_block": latest_block}
    result, err = eth_call(rpc, to_addr, selector, block or "latest")
    if err is not None:
        out.update({"state": "rpc-error", "rpc_error": err, "variants": [],
                    "verdict": "UNKNOWN", "iocs": empty_iocs()})
        return out
    out["rpc_error"] = None
    dec = decode_hex(result if isinstance(result, str) else (result or ""))
    out.update(dec)
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def human_report(r: dict) -> str:
    lines = []
    lines.append("to/selector : %s / %s" % (r.get("to"), r.get("selector")))
    lines.append("rpc         : %s" % r.get("rpc", "(offline)"))
    if r.get("block"):
        blk = r["block"]
        if isinstance(blk, str) and blk.startswith("0x"):
            try:
                blk = "%s (%d)" % (blk, int(blk, 16))
            except ValueError:
                pass
        latest = r.get("latest_block")
        if latest is not None:
            head = "latest %s (%d)" % (hex(latest), latest)
            if isinstance(blk, str) and blk.lower() == "latest":
                blk = head
            else:
                blk = "%s, %s" % (blk, head)
        lines.append("block       : %s" % blk)
    if r.get("block_timestamp"):
        lines.append("block_time  : %s" % time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(r["block_timestamp"]))))
    lines.append("state       : %s" % r.get("state"))
    if r.get("rpc_error"):
        lines.append("rpc_error   : %s" % r["rpc_error"])
    if r.get("state") == "burned/rotated":
        lines.append("verdict     : NEGATIVE (empty return 0x - config burned/rotated)")
        lines.append("note        : this is a finding, not an error")
    lines.append("verdict     : %s" % r.get("verdict"))
    iocs = r.get("iocs") or {}
    if has_iocs(iocs):
        lines.append("iocs        : urls=%s ips=%s domains=%s"
                     % (iocs.get("urls"), iocs.get("ips"), iocs.get("domains")))
    for v in r.get("variants", []):
        lines.append("")
        lines.append("[%s] (printable %.2f)" % (v["method"], v["printable_ratio"]))
        txt = v["text"]
        lines.append(txt if len(txt) <= 800 else txt[:800] + " ...TRUNC")
    if not r.get("variants") and r.get("state") == "ok":
        lines.append("no readable variant decoded from result")
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Universal blockchain dead-drop decoder (etherhiding C2 config)")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--rpc", help="JSON-RPC endpoint URL")
    g.add_argument("--chain", choices=sorted(CHAIN_PRESETS), help="chain preset")
    ap.add_argument("--to", help="contract address 0x<40hex>")
    ap.add_argument("--data", default="0x", help="call data selector 0x<8hex> (default: no data)")
    ap.add_argument("--block", default=None,
                    help="block number (decimal or 0x-hex) or tag; default latest")
    ap.add_argument("--at-time", default=None,
                    help="Unix timestamp (seconds or ms): use the block at or before it")
    ap.add_argument("--resolve-time", default=None,
                    help="print the block at or before a Unix timestamp and exit")
    ap.add_argument("--hex", dest="rawhex", help="offline: decode a raw eth_call result hex")
    args = ap.parse_args(argv)

    if args.rawhex:
        if args.block or args.at_time:
            ap.error("--block/--at-time only apply to live pulls")
        r = decode_hex(args.rawhex)
    elif args.resolve_time is not None:
        rpc = args.rpc or CHAIN_PRESETS.get(args.chain)
        if not rpc:
            ap.error("need --rpc URL or --chain preset")
        bn, bts, err = resolve_block_by_timestamp(rpc, args.resolve_time)
        if err:
            ap.error("could not resolve --resolve-time: %s" % err)
        print("block       : 0x%x (%d)" % (bn, bn))
        print("block_time  : %s" % time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(bts))))
        return 0
    elif args.to:
        rpc = args.rpc or CHAIN_PRESETS.get(args.chain)
        if not rpc:
            ap.error("need --rpc URL or --chain preset (or --hex for offline mode)")
        block = normalize_block(args.block) if args.block else "latest"
        block_ts = None
        if args.at_time is not None:
            if args.block:
                ap.error("use either --block or --at-time, not both")
            bn, bts, err = resolve_block_by_timestamp(rpc, args.at_time)
            if err:
                ap.error("could not resolve --at-time: %s" % err)
            block, block_ts = hex(bn), bts
        latest, _ = latest_block_number(rpc)  # best-effort head for context
        r = pull_and_decode(rpc, args.to, args.data or "0x",
                            block=block, block_ts=block_ts,
                            latest_block=latest)
    else:
        ap.error("need --hex RESULT or (--to ADDR with --rpc/--chain)")

    print(human_report(r))
    return 0


if __name__ == "__main__":
    sys.exit(main())
