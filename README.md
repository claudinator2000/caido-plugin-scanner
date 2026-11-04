# Caido plugin scanner

[![Caido plugin scan](https://github.com/claudinator2000/caido-plugin-scanner/actions/workflows/scan.yml/badge.svg?branch=main&event=schedule)](https://github.com/claudinator2000/caido-plugin-scanner/actions/workflows/scan.yml?query=branch%3Amain+event%3Aschedule)

Scans every plugin in the [Caido](https://caido.io) store for malicious behaviour:
exfiltration of proxy traffic, hidden downloads and command execution, obfuscation,
known-malicious dependencies and tampered packages. New releases are picked up within
30 minutes; all plugins are rescanned daily.

What it is not:

- **Not a vulnerability scanner.** It looks for plugins that act against you, not for
  bugs. Known CVEs in dependencies are listed for context, nothing more.
- **Not proof of safety.** It sets a minimum bar that catches careless or copied
  malware. A motivated attacker who knows the rules can get past it.

**[Latest results →](https://github.com/claudinator2000/caido-plugin-scanner/actions/workflows/scan.yml?query=branch%3Amain+event%3Aschedule)**
Open the newest run and scroll to the table.

## Reading the table

| Status | Meaning |
|---|---|
| 🟢 ok | Nothing that needs a look. |
| 🔴 new | Findings that need a human look, first seen in this run. |
| 🔴 reported | Same findings as before, plugin unchanged. |
| ⚪ no report | The scan did not finish: download, signature or package check failed. See the job log. |

A red row means "read this code", not "this plugin is malicious". Most findings in
legitimate plugins come from bundled libraries or from what the plugin is meant to do,
such as running a command you configured. Expand a row to see the code, a link to the
source line and what the rule looks for.

Accepted findings in this repository are limited to clear false positives, such as
bundled library code or a rule matching plain data. Anything that is a judgement call,
for example a plugin that downloads and starts a binary by design, stays red.

If you think you found a malicious plugin, tell the Caido team and the maintainer
privately rather than in a public issue.

## Your own copy

Run your own copy to scan extra repositories, or to mark findings you have reviewed as
accepted.

1. Create a copy: use **Use this template**, or push a clone to a new repository.
   Keep it private if your accepted findings should stay private; a fork of a public
   repository is always public.
2. Enable Actions.
3. Optional: list extra repositories in [`extra-repos.txt`](extra-repos.txt).

To scan a single repository once, go to **Actions → Caido plugin scan → Run workflow**
and enter `owner/repo`.

To accept a finding, copy its entry from the `baseline-candidates` artifact into
`baselines/<plugin-id>.json` and add a reason (see [`baselines/`](baselines/)). The entry
stops applying when the file changes.

A full scan uses about 100 Actions minutes. That is free in public repositories. In a
private repository, change the schedule at the top of
[`scan.yml`](.github/workflows/scan.yml) so it fits your quota.

## Limits

- Static pattern matching only: nothing is executed or observed at runtime, so a
  determined author can evade it (see above).
- The release ZIP is scanned, but nobody checks that it was built from the repository.
- A valid store signature only proves who published a package.
- Large minified bundles can hide data flows from the rules.

## How it works

For each plugin, a GitHub Actions job does the following:

1. Downloads the latest release and checks its store signature.
2. Unpacks the ZIP under strict checks.
3. Runs [GuardDog](https://github.com/DataDog/guarddog), Semgrep with
   [Caido-specific rules](rules/) and
   [OSV-Scanner](https://github.com/google/osv-scanner) on the lockfile.

Plugin code is never built or run. Incomplete scans count as failures. Details are in the
headers of the scripts in [`scripts/`](scripts/).

To report a vulnerability in the scanner itself, see [SECURITY.md](SECURITY.md).
Licensed under [MIT](LICENSE).
