# Baselines

One file per plugin, `<plugin-id>.json`, listing reviewed findings that no longer block.
Each entry is one of two kinds:

- `false-positive` (the default): the behaviour the rule looks for does not happen at all
  (the match is data, text or a different API). Shows as ok.
- `risk-accepted`: the behaviour is real and the owner accepts it, one finding at a time.
  Needs a `basis`: `plugin-purpose`, `trusted-maintainer`, `hard-to-exploit`,
  `third-party-service` (the risk lies with a service the plugin depends on, such as an
  OAST server) or `other`; the `reason` says the rest. Shows as 🟡 risk accepted.

```json
{"accepted": [
  {"fingerprint": "3f9c…", "reason": "Key code table of the editor, no network or code execution",
   "owner": "<github-user>", "review_by": "2027-05-01",
   "rule": "obf-decode-into-call", "where": "frontend/index.js:120"},
  {"fingerprint": "8a1d…", "kind": "risk-accepted", "basis": "third-party-service",
   "reason": "Registers callbacks with the OAST server the user picks; data leaves by design",
   "owner": "<github-user>", "review_by": "2027-05-01",
   "rule": "threat-network-exfiltration", "where": "backend/index.js:44"}
]}
```

Copy entries from the `baseline-candidates` artifact of a scan run and fill in `reason`,
`owner` and `review_by`. An entry stops applying when the file it refers to changes or when
`review_by` has passed; an update of the plugin therefore always needs a new review.
