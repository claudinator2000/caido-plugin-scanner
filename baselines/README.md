# Baselines

One file per plugin, `<plugin-id>.json`, listing reviewed findings that no longer block.
This repository accepts clear false positives only: the behaviour the rule looks for does not
happen at all (the match is data, text or a different API). Behaviour that does happen stays
red here, even when it is harmless; accept it in your own private copy if
you want (see the main README).

```json
{"accepted": [
  {"fingerprint": "3f9c…", "reason": "Telemetry to caido.io, reviewed in code",
   "owner": "<github-user>", "review_by": "2027-05-01",
   "rule": "caido-hardcoded-external-url", "where": "backend/index.js:12"}
]}
```

Copy entries from the `baseline-candidates` artifact of a scan run and fill in `reason`,
`owner` and `review_by`. An entry stops applying when the file it refers to changes or when
`review_by` has passed.
