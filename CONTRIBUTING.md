# Contributing

Python standard library only. No new dependencies — the decoder must stay dependency-free and never execute decoded content.

## Highest value: campaign snapshots

`campaign_snapshots.json` holds real `eth_call` hex for known etherhiding campaigns, captured at pinned blocks. New campaigns/actors are the main coverage gap.

Each entry needs:

```json
{
  "name": "actor-slug",
  "rpc": "https://...",
  "to": "0x<40hex>",
  "data": "0x<selector>",
  "block": "0x<hex>",
  "hex": "0x<raw eth_call result>"
}
```

Capture at a **pinned block, never `latest`** — dead-drops rotate and burn, and only historical state is a stable test invariant. Add the expected `(verdict, method substring, ioc substring)` to `CAMPAIGN_EXPECT` in `test_decode_dd.py`.

The snapshot file is committed alongside the code, so adding vectors is a code contribution and goes through review.

## Other contributions

- **Encoding layers** — `decode_dd.py` tries ABI strings, raw UTF-8, base64, gzip+base64, single-byte XOR and repeating-key XOR. New obfuscation seen in the wild (other key lengths, custom alphabets, new nesting) belongs there, plus a synthetic unit vector in layer 1 of `test_decode_dd.py`.
- **Chain presets** — `CHAIN_PRESETS` in `decode_dd.py` (currently eth/polygon/bsc/base). Adding chains or better public RPC endpoints is easy.
- **IOC extraction / verdict heuristics** — `find_iocs()` and `looks_malicious()` are heuristic. False positives and negatives on real samples are useful reports; send the sample hex rather than a description.

## Before opening a PR

```sh
uv run test_decode_dd.py                 # offline: must be ALL PASS
uv run test_decode_dd.py --live          # pinned-block re-pull (needs an archive RPC)
uv run test_decode_dd.py --live --latest # chain-head re-pull (informational)
```

Vectors whose RPC refuses historical state (`archive requests require a personal token`, `missing trie node`) are reported as **SKIP**, not failed — point `rpc` at an archive endpoint in `campaign_snapshots.json` to exercise them.
