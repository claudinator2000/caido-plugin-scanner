#!/usr/bin/env python3
"""Selects the plugins a run has to scan and remembers what was scanned.

Usage:
  watch.py select <full|changed> <plugins.json> <state.json> <config-hash> <baselines-dir>
                  <matrix.json> <keys.json> <summary.md>
  watch.py update <state.json> <keys.json> <matrix.json> <reports-dir> <new-state.json>
                  <report-cache-dir>

Every plugin gets a key of four parts:
- plugin state: asset ID, update time and digest of plugin_package.zip in the latest
  release (GitHub API) and the commit of the release tag whose lockfiles OSV checks
  (without a release asset, the HEAD commit of the default branch, which is then the
  scan target);
- hash of the scanner configuration (rules, scripts, workflow with tool versions);
- hash of baselines/<id>.json and the number of entries expired today (findings.py no
  longer accepts them; without this part an expiry would only take effect in the full scan);
- hash of the public_key from the store entry that the package signature is checked against.
In "changed" mode a run scans only plugins whose key changed since their last scan. "full"
mode scans all of them.

Fail closed: a plugin whose state cannot be determined is scanned. If that applies to more
than MAX_UNKNOWN plugins (e.g. an API outage), the run fails instead of spending the minute
budget on a full scan. A plugin counts as scanned only once its scan produced a report; if
a selected plugin has no report, its old state is dropped and the next run repeats the
scan. Without a stored state, everything is scanned.

Store entries and API responses are untrusted data: key parts are checked against fixed
patterns, invalid values count as "not determinable".

One alert per finding: for every plugin, the state remembers the blocking findings a scan
reported for the plugin's current state (the key without configuration, baseline and store
key). select passes them as "known" in the matrix, and findings.py does not fail the job
for them again. A new plugin state (update) starts without reported findings, so every
finding alerts again.

For the overview, update stores a reduced copy of every verified report in the report
cache; the overview then shows all plugins in every run, not only the scanned ones.
"""
import concurrent.futures, datetime, hashlib, json, os, re, subprocess, sys, urllib.error, urllib.request
from pathlib import Path

ASSET_NAME = "plugin_package.zip"
MAX_UNKNOWN = 10
API = "https://api.github.com"

ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
REPO_PATTERN = re.compile(r"^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$")
TIME_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$")
# As in fetch-target.sh: only these characters in release tags (all store tags 11/2026)
TAG_PATTERN = re.compile(r"^[A-Za-z0-9._+-]{1,128}$")
HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")
FINGERPRINT_PATTERN = re.compile(r"^[0-9a-f]{16}$")


class LookupFailed(Exception):
    pass


def github_release(repo):
    """Latest release (without pre-releases and drafts, like .../releases/latest/download)
    or None if there is none."""
    req = urllib.request.Request(f"{API}/repos/{repo}/releases/latest", headers={
        "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
        **({"Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}"} if os.environ.get("GITHUB_TOKEN") else {})})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise LookupFailed(f"HTTP {e.code}")
    except (OSError, ValueError) as e:
        raise LookupFailed(type(e).__name__)


def git_commit(repo, ref):
    """Commit that ref points to (for annotated tags the commit behind it), None on error."""
    try:
        out = subprocess.run(["git", "ls-remote", "--", f"https://github.com/{repo}.git", ref, f"{ref}^{{}}"],
                             capture_output=True, text=True, timeout=60,
                             env={**os.environ, "GIT_TERMINAL_PROMPT": "0"}).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    refs = dict(reversed(line.split("\t", 1)) for line in out.splitlines() if "\t" in line)
    return refs.get(f"{ref}^{{}}") or refs.get(ref)


def key_for(repo, get_release=github_release, get_commit=git_commit):
    """State of a plugin as a string, or None if it cannot be determined.
    With a release asset: the asset and the commit of the release tag whose lockfile OSV checks.
    Without: the HEAD commit of the default branch, whose source is scanned."""
    try:
        release = get_release(repo)
    except LookupFailed:
        return None
    asset = next((a for a in (release or {}).get("assets") or []
                  if isinstance(a, dict) and a.get("name") == ASSET_NAME), None)
    if asset is None:
        head = get_commit(repo, "HEAD")
        if not (isinstance(head, str) and SHA_PATTERN.match(head)):
            return None
        return f"repo={repo};head={head}"
    aid, updated, digest = asset.get("id"), asset.get("updated_at"), asset.get("digest")
    tag = release.get("tag_name")
    if not (type(aid) is int and isinstance(updated, str) and TIME_PATTERN.match(updated)
            and (digest is None or (isinstance(digest, str) and DIGEST_PATTERN.match(digest)))
            and isinstance(tag, str) and TAG_PATTERN.match(tag)):
        return None
    commit = get_commit(repo, f"refs/tags/{tag}")
    if not (isinstance(commit, str) and SHA_PATTERN.match(commit)):
        return None
    return f"repo={repo};asset={aid};updated={updated};digest={digest or '-'};tag={tag};commit={commit}"


def baseline_state(path, today):
    """Hash of the baseline and number of entries whose review_by is before today
    (like findings.entry_problem). "-" without a baseline."""
    try:
        data = Path(path).read_bytes()
    except OSError:
        return "-"
    expired = 0
    try:
        entries = json.loads(data).get("accepted") or []
    except (ValueError, AttributeError):
        entries = []
    for e in entries if isinstance(entries, list) else []:
        try:
            if datetime.date.fromisoformat(e["review_by"]) < today:
                expired += 1
        except (TypeError, KeyError, ValueError):
            pass  # invalid entries suppress nothing anyway, regardless of the date
    return f"{hashlib.sha256(data).hexdigest()}:{expired}"


def full_key(state_key, config_hash, baseline_hash, public_key):
    """Key from state, configuration, baseline and store key (as a hash; if it changes or
    disappears, the signature is checked again)."""
    if state_key is None:
        return None
    key = hashlib.sha256(public_key.encode()).hexdigest() if public_key else "-"
    return f"{state_key};config={config_hash};baseline={baseline_hash};key={key}"


def parts(key):
    return dict(p.split("=", 1) for p in key.split(";"))


def reason(old, new):
    if new is None:
        return "state not determinable"
    if old is None:
        return "new"
    o, n = parts(old), parts(new)
    rest = lambda d: {k: v for k, v in d.items() if k not in ("config", "baseline", "key")}
    why = []
    if rest(o) != rest(n):
        why.append("release/repository state changed")
    if o.get("config") != n.get("config"):
        why.append("scanner configuration changed")
    if o.get("baseline") != n.get("baseline"):
        same_file = o.get("baseline", "").split(":")[0] == n.get("baseline", "").split(":")[0]
        why.append("baseline exception expired" if same_file else "baseline changed")
    if o.get("key") != n.get("key"):
        why.append("store key changed")
    return ", ".join(why) or None


def select(plugins, keys, state, full=False):
    chosen = []
    for p in plugins:
        why = reason(state.get(p["id"]), keys.get(p["id"]))
        if full:
            chosen.append((p, "full run"))
        elif why:
            chosen.append((p, why))
    return chosen


def read_state_file(path):
    try:
        data = json.loads(Path(path).read_text())
        return data if isinstance(data, dict) and data.get("version") == 1 else {}
    except (OSError, ValueError):
        return {}


def load_state(path):
    plugins = read_state_file(path).get("plugins")
    if not isinstance(plugins, dict):
        return {}
    return {k: v for k, v in plugins.items() if isinstance(k, str) and isinstance(v, str)}


def load_reported(path):
    """Reported blocking findings per plugin: {id: {"plugin": state, "fps": [...]}}.
    Invalid entries are dropped (then the next finding alerts again)."""
    reported = read_state_file(path).get("reported")
    if not isinstance(reported, dict):
        return {}
    ok = lambda v: (isinstance(v, dict) and isinstance(v.get("plugin"), str) and isinstance(v.get("fps"), list)
                    and all(isinstance(f, str) and FINGERPRINT_PATTERN.match(f) for f in v["fps"]))
    return {k: v for k, v in reported.items() if isinstance(k, str) and ID_PATTERN.match(k) and ok(v)}


def save_state(path, state, reported=None):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps({"version": 1, "plugins": state, "reported": reported or {}},
                                     indent=1, sort_keys=True) + "\n")


def plugin_state(key):
    """The part of the key that describes the plugin state (without configuration, baseline
    and store key)."""
    return ";".join(f"{k}={v}" for k, v in parts(key).items() if k not in ("config", "baseline", "key"))


def known_for(reported, pid, key):
    entry = reported.get(pid)
    if not key or not entry or entry["plugin"] != plugin_state(key):
        return []
    return sorted(entry["fps"])


def scanned(report_dir, key):
    """Did the scan produce what the key describes? A report exists, and for a release asset
    the ZIP was scanned (sha256.txt from fetch-target.sh) with the digest from the API, if it
    provides one, and the source for OSV comes from the commit of the release tag
    (source.txt). Without a release asset, the scanned source comes from the selected HEAD
    (source.txt). Otherwise, e.g., the download failed or the plugin changed during the run.
    Key, reported findings and report cache all depend on this check."""
    if not (report_dir / "report.json").is_file():
        return False
    p = parts(key)
    try:
        source = dict(line.split(" ", 1) for line in (report_dir / "source.txt").read_text().splitlines()
                      if " " in line)
    except OSError:
        return False
    if "asset" not in p:
        # Source scan: the cloned HEAD must be the selected one (push between selection
        # and scan)
        return source.get("commit") == p.get("head")
    try:
        scanned_sha = (report_dir / "sha256.txt").read_text().split()[0]
    except (OSError, IndexError):
        return False
    if source.get("commit") != p.get("commit"):
        return False
    return p.get("digest") == "-" or p.get("digest") == f"sha256:{scanned_sha}"


def update_reported(reported, keys, reports, selected):
    """Reported findings for verified scans: all blocking findings of the report, bound to
    the scanned plugin state. With an unchanged state they are added to the ones already
    reported: a finding that is absent for a while (accepted in the baseline, rule disabled)
    does not alert again when it returns. A new state starts empty. Without a verified scan,
    the old entry stays."""
    new = dict(reported)
    for pid in selected:
        key = keys.get(pid)
        d = Path(reports) / f"report-{pid}"
        if not (key and ID_PATTERN.match(pid) and scanned(d, key)):
            continue
        try:
            blocking = json.loads((d / "report.json").read_text()).get("new_blocking") or {}
        except (OSError, ValueError, AttributeError):
            continue
        fps = {f for f in blocking if isinstance(f, str) and FINGERPRINT_PATTERN.match(f)}
        state = plugin_state(key)
        if pid in reported and reported[pid]["plugin"] == state:
            fps |= set(reported[pid]["fps"])
        new[pid] = {"plugin": state, "fps": sorted(fps)}
    return new


CACHED_FIELDS = ("plugin", "version", "new_blocking", "known_blocking", "accepted", "baseline_problems")


def cache_reports(keys, reports, selected, cache_dir, scanned_at, run_url):
    """Reduced copy of every verified report for the overview of later runs."""
    Path(cache_dir).mkdir(parents=True, exist_ok=True)
    for pid in selected:
        key = keys.get(pid)
        d = Path(reports) / f"report-{pid}"
        if not (key and ID_PATTERN.match(pid) and scanned(d, key)):
            continue
        try:
            rep = json.loads((d / "report.json").read_text())
        except (OSError, ValueError):
            continue
        small = {k: rep.get(k) for k in CACHED_FIELDS}
        small["new_info"] = {k: {"rule": v.get("rule"), "where": v.get("where")}
                             for k, v in (rep.get("new_info") or {}).items()}
        small["scanned_at"], small["run_url"] = scanned_at, run_url
        (Path(cache_dir) / f"{pid}.json").write_text(json.dumps(small))


def update(state, keys, reports, selected):
    """Take over the keys of selected plugins whose scan checked the state from the key. For
    the other selected plugins (scan incomplete, different target) the old state is dropped
    and the next run repeats the scan; plugins not selected keep theirs."""
    new = dict(state)
    for pid in selected:
        key = keys.get(pid)
        if key and ID_PATTERN.match(pid) and scanned(Path(reports) / f"report-{pid}", key):
            new[pid] = key
        else:
            new.pop(pid, None)
    return new


def summary_md(chosen, total, full=False):
    head = "## Selection\n\n"
    if not chosen:
        return head + f"No changes: none of the {total} plugins needs a new scan.\n"
    mode = "Full run" if full else "Changed plugins only"
    # Only the table is collapsed: mode and count stay visible
    lines = [head + f"{mode}: {len(chosen)} of {total} plugins are scanned.\n",
             "<details><summary>Plugins and reason</summary>", "",
             "| Plugin | Reason |", "|---|---|"]
    for p, why in chosen:
        # id and repo were checked for safe characters when the list was built
        lines.append(f"| [{p['id']}](https://github.com/{p['repo']}) | {why} |")
    lines += ["", "</details>"]
    return "\n".join(lines) + "\n"


def cmd_select(mode, plugins_file, state_file, config_hash, baselines, matrix_out, keys_out, summary_out):
    if mode not in ("full", "changed") or not HASH_PATTERN.match(config_hash):
        sys.exit("Invalid mode or configuration hash")
    plugins = json.loads(Path(plugins_file).read_text())
    if not all(ID_PATTERN.match(p["id"]) and REPO_PATTERN.match(p["repo"]) for p in plugins):
        sys.exit("Invalid plugin list")
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        states = dict(zip([p["id"] for p in plugins], pool.map(lambda p: key_for(p["repo"]), plugins)))
    today = datetime.date.today()
    keys = {p["id"]: full_key(states[p["id"]], config_hash, baseline_state(Path(baselines) / f"{p['id']}.json", today),
                              p.get("public_key") or "")
            for p in plugins}
    unknown = [pid for pid, k in keys.items() if k is None]
    if unknown:
        print(f"State not determinable for {len(unknown)} plugins: {', '.join(unknown)}")
    if mode == "changed" and len(unknown) > MAX_UNKNOWN:
        sys.exit(f"More than {MAX_UNKNOWN} plugins without a determinable state (API outage?); "
                 "run aborted instead of scanning all of them")
    chosen = select(plugins, keys, load_state(state_file), full=(mode == "full"))
    reported = load_reported(state_file)
    # known_state: the plugin state that known belongs to; findings.py checks it against the
    # actually scanned target (an update between selection and scan cancels known)
    matrix = [dict(p, known=known_for(reported, p["id"], keys.get(p["id"])),
                   known_state=plugin_state(keys[p["id"]]) if keys.get(p["id"]) else "")
              for p, _ in chosen]
    Path(matrix_out).write_text(json.dumps(matrix))
    Path(keys_out).write_text(json.dumps(keys))
    Path(summary_out).write_text(summary_md(chosen, len(plugins), full=(mode == "full")))
    print(f"{len(chosen)} of {len(plugins)} plugins selected")
    return 0


def cmd_update(state_file, keys_file, matrix_file, reports, out, cache_dir):
    keys = json.loads(Path(keys_file).read_text())
    selected = {p["id"] for p in json.loads(Path(matrix_file).read_text())}
    reported = update_reported(load_reported(state_file), keys, reports, selected)
    save_state(out, update(load_state(state_file), keys, reports, selected), reported)
    run_url = os.environ.get("RUN_URL", "")
    cache_reports(keys, reports, selected, cache_dir, datetime.date.today().isoformat(),
                  run_url if run_url.startswith("https://github.com/") else "")
    return 0


if __name__ == "__main__":
    commands = {"select": (cmd_select, 8), "update": (cmd_update, 6)}
    if len(sys.argv) < 2 or sys.argv[1] not in commands or len(sys.argv) - 2 != commands[sys.argv[1]][1]:
        sys.exit(__doc__)
    sys.exit(commands[sys.argv[1]][0](*sys.argv[2:]))
