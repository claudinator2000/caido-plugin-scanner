# Baselines

One file per plugin, `<plugin-id>.json`, listing the findings you reviewed and accepted.
This public repository ships none: acceptance is a judgement call, so keep your baselines
in your own private copy (see the main README).

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
