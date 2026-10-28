# Blockchain DDR Decoder

A toolkit to pull and decode dead-drop resolvers from the blockchain — the "etherhiding" technique where malware stores its C2 configuration in public smart contracts and reads it back over read-only `eth_call` JSON-RPC.

Given a contract address and call selector it pulls the stored value from a public RPC, decodes it, and reports the URLs, IPs, domains, and contract addresses it finds. It can also decode a result hex captured elsewhere, entirely offline.

It works by issuing a `eth_call` JSON-RPC call, then trying every known encoding layer in order: ABI-encoded strings, raw UTF-8, base64, gzip+base64, single-byte XOR, and repeating-key XOR, including a deep recovery pass for keys the fast heuristic misses, while recursing into nested blobs. Every decoded variant is scanned for IOCs and script indicators to produce a POSITIVE/NEGATIVE verdict. Decoded content is attacker-controlled data, so nothing is ever executed: only string operations, Python standard library only.

> The objective of this toolkit is to extract and decode dead drops values from the blockchain. It does not aim to document the campaigns or malwares themselves.

## Tools

| File                | Purpose                                                                                   |
| ------------------- | ----------------------------------------------------------------------------------------- |
| `decode_dd.py`      | Universal dead-drop decoder (offline hex or live `eth_call`)                              |
| `test_decode_dd.py` | Regression tests: offline unit vectors + real campaign snapshots, opt-in `--live` re-pull |

## Usage

```sh
# live pull from a chain preset (eth / polygon / bsc / base)
uv run decode_dd.py --chain polygon --to 0x1823A9a0Ec8e0C25dD957D0841e3D41a4474bAdc --data 0x3bc5de30

# custom RPC, or at a specific block / time
uv run decode_dd.py --rpc https://... --to 0x<40hex> --data 0x<8hex>
uv run decode_dd.py --chain eth --to 0x<40hex> --data 0x<8hex> --block 25678470
uv run decode_dd.py --chain eth --to 0x<40hex> --data 0x<8hex> --at-time 1754...

# offline: decode a captured eth_call result hex
uv run decode_dd.py --hex 0x...
```

Importable API: `decode_hex(hexstr)`, `pull_and_decode(rpc, to, selector, block)`,
`resolve_block_by_timestamp(rpc, ts)`.

## Tests

```sh
uv run test_decode_dd.py                 # offline: unit vectors + campaign snapshots
uv run test_decode_dd.py --live          # also re-pull campaign snapshots at their pinned blocks
uv run test_decode_dd.py --live --latest # also re-pull every drop at the chain head
```

Campaign regression snapshots (`campaign_snapshots.json`) are the raw `eth_call` results of real dead-drops (troyden, deadlock, CLEARFAKE, JADESNOW, ether, nochain-sw, amatera, chaindrop) captured at pinned blocks on 2026-10-27: known working examples must always keep working, offline and deterministic. The `--live` mode re-reads the same pinned blocks via public RPC — never "latest", since dead-drops rotate and burn over time.

`--live --latest` flips that: it re-reads each drop at the current chain head and reports what it says now. The decoded value is *not* an invariant there — a rotated or burned drop is a valid result — so it only asserts the RPC answers and the decoder returns a sane state.

Pinned-block `--live` needs an archive RPC. Where the endpoint refuses historical state (`archive requests require a personal token`, `missing trie node`) the vector is reported as **SKIP**, not failed.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT License — see [LICENSE](LICENSE).
