#!/usr/bin/env python3
"""Normalizes GuardDog, Semgrep, OSV and inventory results into stable fingerprints
and compares them with a reviewed baseline.

Usage: findings.py <plugin-id> <guarddog.json> <semgrep.json> <osv.json> <inventory.json>
                   <baseline.json> <out.json> [<src-dir> <source.txt> <owner/repo> <release|source>]

With the optional details of the cloned source, every finding whose file exists in the
repository at the scanned commit gets a link to it (see add_source_links).

Exit 0: no new blocking findings.
Exit 1: new blocking findings (report written).

Blocking findings that were already reported (environment variable KNOWN_BLOCKING, a JSON
list of fingerprints from the watch.py state for the same plugin state) stay blocking in
the report but do not fail the job again: one alert per finding and plugin state. They
apply only if the scanned target matches the state in KNOWN_STATE (commit from
source.txt, SHA-256 of the ZIP from sha256.txt next to it): an update between selection
and scan reports everything again. Invalid or missing values count as empty, and the job
fails again.
Exit 2: scanner output missing or incomplete, baseline unreadable (no report).

Scanner errors (GuardDog errors, Semgrep timeouts) are findings themselves: an incomplete
scan blocks until it is fixed or accepted in the baseline with a reason.

Every finding that refers to a file is bound to its content (SHA-256 of the file in the
fingerprint): when the file changes, no exception applies any more and all findings of
that file have to be reviewed again. The reported match alone is not enough, because the
reviewed behavior depends on code outside the match (e.g. the definition of payload in
eval(payload)).
GuardDog paths are relative to the scan target (default: ./target).
"""
import datetime, hashlib, json, os, re, sys
from pathlib import Path
from urllib.parse import quote

ENTRY_FIELDS = ("reason", "owner", "review_by")
# "false-positive" (default): the behaviour the rule looks for does not happen.
# "risk-accepted": it happens and the owner accepts it; the reason says why.
KINDS = ("false-positive", "risk-accepted")

class ScanIncomplete(Exception):
    pass


def load_scan(path, required_key):
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, ValueError) as e:
        raise ScanIncomplete(f"{path}: not readable ({e})")
    if not isinstance(data, dict) or required_key not in data:
        raise ScanIncomplete(f"{path}: key '{required_key}' missing, the scan did not complete")
    return data


def norm(code):
    # Normalize whitespace, for display only. Fingerprints hash the unchanged match:
    # whitespace can carry meaning (e.g. a line break in a template literal that ends a
    # comment).
    return re.sub(r"\s+", " ", code or "").strip()


def excerpt(code):
    return code[:300]


def rel(path):
    # Path relative to the scan target, so fingerprints do not depend on the working directory
    path = path or ""
    return path[len("target/"):] if path.startswith("target/") else path


def src_lines(x):
    # Semgrep CE returns only "requires login" in "lines" -> read exactly the reported range
    # from the file. start/end.offset are byte offsets (end exclusive); Semgrep also counts
    # columns in bytes, so slicing is done on bytes.
    # The range is the fingerprint content, also in minified one-liners.
    try:
        data = Path(x["path"]).read_bytes()
        start, end = x["start"], x["end"]
        if "offset" in start and "offset" in end:
            span = data[start["offset"] : end["offset"]]
        else:
            # Without offsets: line/column, columns also in bytes (1-based, end exclusive)
            lines = data.split(b"\n")[start["line"] - 1 : end["line"]]
            lines[-1] = lines[-1][: end["col"] - 1]
            lines[0] = lines[0][start["col"] - 1 :]
            span = b"\n".join(lines)
        return span.decode("utf-8", errors="replace")
    except Exception:
        return x.get("extra", {}).get("lines", "")


def file_digest(path):
    """SHA-256 of the file. A finding without a readable file cannot be bound."""
    if not path:
        return ""
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError as e:
        raise ScanIncomplete(f"{path}: file of the finding not readable ({e})")


def target_digest(root):
    h = hashlib.sha256()
    base = Path(root)
    if not base.is_dir():
        raise ScanIncomplete(f"{root}: scan target not readable")
    for f in sorted(p for p in base.rglob("*") if p.is_file()):
        h.update(str(f.relative_to(base)).encode() + b"\0")
        h.update(hashlib.sha256(f.read_bytes()).digest())
    return h.hexdigest()


# Enrichment for the report (not part of the fingerprints)
CONTEXT_BYTES = 240
# esbuild/Vite write a comment with the module path in front of every bundled module
ORIGIN_COMMENT = re.compile(rb"^[ \t]*// ((?:node_modules|packages|src|lib|apps)/[^\r\n]{1,300})$", re.M)
_origin_cache = {}


def library_of(path):
    """Library name (with version, if the path contains it) from a node_modules path."""
    m = re.search(r"node_modules/\.pnpm/((?:@[^/+]+\+)?[^/@]+)@([^/_]+)", path)
    if m:
        return f"{m.group(1).replace('+', '/')}@{m.group(2)}"
    m = re.search(r"node_modules/((?:@[^/]+/)?[^/]+)", path)
    return m.group(1) if m else None


def origin_at(path, offset):
    """Last module path comment before offset. The comment is part of the plugin file and
    therefore an unverified statement of the plugin."""
    if path not in _origin_cache:
        try:
            data = Path(path).read_bytes()
        except OSError:
            data = b""
        _origin_cache[path] = [(m.start(), m.group(1).decode("utf-8", "replace"))
                               for m in ORIGIN_COMMENT.finditer(data)]
    best = None
    for pos, comment in _origin_cache[path]:
        if pos >= offset:
            break
        best = comment
    if best is None:
        return None
    if "node_modules/" in best:
        return {"kind": "library", "name": library_of(best), "path": best}
    return {"kind": "plugin", "name": None, "path": best}


def context_at(data, start, end):
    dec = lambda b: b.decode("utf-8", errors="replace")
    return {"before": dec(data[max(0, start - CONTEXT_BYTES):start]),
            "match": dec(data[start:end]),
            "after": dec(data[end:end + CONTEXT_BYTES])}


def semgrep_context(x):
    try:
        data = Path(x["path"]).read_bytes()
        s, e = x["start"].get("offset"), x["end"].get("offset")
        if s is None or e is None:
            lines = data.split(b"\n")
            s = sum(len(l) + 1 for l in lines[: x["start"]["line"] - 1]) + x["start"]["col"] - 1
            e = sum(len(l) + 1 for l in lines[: x["end"]["line"] - 1]) + x["end"]["col"] - 1
        return context_at(data, s, e), origin_at(x["path"], s)
    except Exception:
        return None, None


def guarddog_context(path, location, match):
    """GuardDog reports file:line; the match is searched around that line. If the signature
    occurs several times in the window, an occurrence that touches the reported line wins,
    otherwise the nearest one."""
    try:
        data = Path(path).read_bytes()
        line = int(str(location).rsplit(":", 1)[1])
        lines = data.split(b"\n")
        line_start = sum(len(l) + 1 for l in lines[: line - 1])
        # GuardDog's line number can lie beyond the end of the file
        line_end = line_start + (len(lines[line - 1]) if 0 < line <= len(lines) else 0)
        window_start = max(0, line_start - 2 * CONTEXT_BYTES)
        window_end = line_start + sum(len(l) + 1 for l in lines[line - 1: line + 2])
        needle = (match or "").encode()
        hits, pos = [], data.find(needle, window_start, window_end) if needle else -1
        while pos >= 0:
            hits.append(pos)
            pos = data.find(needle, pos + 1, window_end)
        distance = lambda p: 0 if p <= line_end and p + len(needle) >= line_start \
            else min(abs(p - line_start), abs(p + len(needle) - line_end))
        pos = min(hits, key=distance) if hits else -1
        s, e = (pos, pos + len(needle)) if pos >= 0 else (line_start, line_end)
        return context_at(data, s, e), origin_at(path, s)
    except Exception:
        return None, None


def match_digest(raw):
    """SHA-256 of the complete, unchanged match: identifies identical matches across
    plugins in the report, even when the displayed excerpt is shortened."""
    return hashlib.sha256((raw or "").encode()).hexdigest()


def fp(*parts):
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def location_line(location):
    try:
        return int(str(location).rsplit(":", 1)[1])
    except (IndexError, ValueError):
        return None


# Links into the source: display only, not part of the fingerprints
REPO_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
MAX_SOURCE_BYTES = 2 * 1024 * 1024
JS_WORDS = {"await", "async", "const", "let", "var", "function", "return", "new", "this",
            "true", "false", "null", "void", "typeof", "import", "from", "export", "default"}


TAG_PATTERN = re.compile(r"^[A-Za-z0-9._+-]{1,128}$")


def read_source(source_file):
    """{"ref": ..., "commit": ...} from source.txt (written by fetch-target.sh)."""
    return dict(l.strip().split(" ", 1) for l in Path(source_file).read_text().splitlines() if " " in l.strip())


def scanned_version(source_file, mode):
    """Release tag or commit of the scanned target for the overview; None if unknown."""
    try:
        source = read_source(source_file)
    except (OSError, ValueError):
        return None
    ref, commit = source.get("ref", ""), source.get("commit", "")
    if not COMMIT_PATTERN.match(commit):
        return None
    if mode == "release" and TAG_PATTERN.match(ref):
        return {"tag": ref, "commit": commit}
    return {"commit": commit}


def source_files(src_root):
    base = Path(src_root)
    return sorted(p.relative_to(base).as_posix() for p in base.rglob("*")
                  if p.is_file() and "node_modules" not in p.relative_to(base).parts)


def resolve_origin(origin_path, files):
    """File in the repository for the bundle's path comment. Bundlers write the path
    relative to their working directory, which can be a subfolder in a monorepo. Only a
    unique match counts."""
    hits = [f for f in files if f == origin_path or f.endswith("/" + origin_path)]
    return hits[0] if len(hits) == 1 else None


def squeeze(s):
    return re.sub(r"\s+", "", s)


def words_of(line):
    return set(re.findall(r"[A-Za-z_$][\w$]{2,}", line)) - JS_WORDS


def has_words(line, words):
    return all(re.search(r"(?<![\w$])" + re.escape(w) + r"(?![\w$])", line) for w in words)


def disambiguate(lines, hits, before):
    """Several candidates (e.g. the same call in three places): the candidate preceded by
    most of the last lines before the match in the bundle. Only a unique winner counts."""
    recent = [l for l in (before or "").splitlines()[-CONTEXT_LINES:] if words_of(l)]
    if not recent:
        return None
    exact = [squeeze(l) for l in recent]
    words = [words_of(l) for l in recent]

    def score(i):
        window = lines[max(0, i - 2 * CONTEXT_LINES):i]
        flat = [squeeze(l) for l in window]
        # Identical lines first, then lines with the same identifiers (transpiled)
        return (sum(any(e in l for l in flat) for e in exact),
                sum(any(has_words(l, w) for l in window) for w in words))
    scores = {i: score(i) for i in hits}
    best = max(scores.values())
    winners = [i for i, s in scores.items() if s == best]
    return winners[0] if best > (0, 0) and len(winners) == 1 else None


def find_line(text, match, before=None):
    """Source line of a bundle match, only if unique. The bundle is transpiled (e.g. 0o755
    becomes 493): first the first match line without whitespace, otherwise a line that
    contains all identifiers of that line. The code before the match decides between
    several candidates (disambiguate)."""
    first = next((l.strip() for l in (match or "").splitlines() if l.strip()), "")
    if not first:
        return None
    lines = text.splitlines()
    needle = squeeze(first)
    hits = []
    if len(needle) >= 6:
        hits = [i for i, l in enumerate(lines) if needle in squeeze(l)]
    if not hits:
        words = words_of(first)
        hits = [i for i, l in enumerate(lines) if words and has_words(l, words)]
    if len(hits) > 1:
        winner = disambiguate(lines, hits, before)
        hits = [winner] if winner is not None else hits
    return hits[0] + 1 if len(hits) == 1 else None


CONTEXT_LINES = 10


def bundle_before(target_root, v, cache):
    """The lines before the match from the scanned file; the context in the report (240
    bytes) is not enough when the same call with the same preparation occurs several times."""
    f, line = v.get("file"), v.get("line")
    if not (f and isinstance(line, int) and line > 1):
        return (v.get("context") or {}).get("before")
    key = ("bundle", f)
    if key not in cache:
        try:
            data = (Path(target_root) / f).read_bytes()[:8 * MAX_SOURCE_BYTES]
            cache[key] = data.decode("utf-8", "replace").splitlines()
        except OSError:
            cache[key] = []
    return "\n".join(cache[key][max(0, line - 1 - CONTEXT_LINES):line - 1]) or None


SOURCE_SUFFIXES = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx", ".vue", ".svelte"}
MIN_SEARCH_NEEDLE = 12


def search_sources(base, files, ctx, cache):
    """Fallback without a path comment (e.g. a Vite frontend): the bundle line with the match,
    without whitespace, occurs in exactly one line of all source files. If the whole line
    matches nowhere (transpiled), the match itself is enough when it is long enough."""
    match = ctx.get("match") or ""
    first = next((l for l in match.splitlines() if l.strip()), "")
    head = (ctx.get("before") or "").rsplit("\n", 1)[-1]
    tail = (ctx.get("after") or "").split("\n", 1)[0] if "\n" not in match else ""
    for needle in (squeeze(head + first + tail), squeeze(first)):
        if len(needle) < MIN_SEARCH_NEEDLE:
            continue
        hits = []
        for f in files:
            if Path(f).suffix not in SOURCE_SUFFIXES:
                continue
            if f not in cache:
                data = (base / f).read_bytes()
                cache[f] = data.decode("utf-8", "replace").splitlines() if len(data) <= MAX_SOURCE_BYTES else []
            hits += [(f, i + 1) for i, l in enumerate(cache[f]) if needle in squeeze(l)]
            if len(hits) > 1:
                break
        if len(hits) == 1:
            return hits[0]
        if len(hits) > 1:
            return None, None
    return None, None


def add_source_links(found, src_root, commit, repo, mode, target_root="target"):
    """Sets "source" (path, line, URL) for findings whose file exists in the cloned
    repository at the scanned commit.
    - source: the scan target is the source itself; path and line apply directly.
    - release: the bundle is not in the repository. The path comment before the match
      (origin) names the source file; it must exist uniquely in the repository. The line
      is searched and left out when it is not unique."""
    if not (repo and REPO_PATTERN.match(repo) and commit and COMMIT_PATTERN.match(commit)):
        return
    base = Path(src_root)
    files, cache = None, {}
    for v in [x for f in found.values() for x in [f, *f.get("also", [])]]:
        path, line, how = None, None, None
        origin = v.get("origin") or {}
        ctx = v.get("context") or {}
        if mode == "source" and v.get("file") and (base / v["file"]).is_file():
            path, line, how = v["file"], v.get("line"), "scanned"
        elif mode == "release" and origin.get("kind") == "plugin":
            if files is None:
                files = source_files(base)
            path, how = resolve_origin(origin["path"], files), "origin"
            if path and ctx:
                data = (base / path).read_bytes()[:MAX_SOURCE_BYTES]
                line = find_line(data.decode("utf-8", "replace"), ctx.get("match"),
                                 bundle_before(target_root, v, cache))
        elif mode == "release" and not origin and ctx:
            if files is None:
                files = source_files(base)
            path, line = search_sources(base, files, ctx, cache)
            how = "search"
        if not path:
            continue
        url = f"https://github.com/{repo}/blob/{commit}/{quote(path)}"
        if isinstance(line, int) and line > 0:
            url += f"#L{line}"
        else:
            line = None
        v["source"] = {"path": path, "line": line, "url": url, "how": how}


def put(found, key, finding):
    """An identical match in several places of the same file has one fingerprint (bound to
    the content, one exception covers all). The further locations are kept under "also"
    for display."""
    if key in found:
        extra = {k: finding.get(k) for k in ("where", "file", "line", "context", "origin")}
        found[key].setdefault("also", []).append(extra)
    else:
        found[key] = finding


def collect(gd, sg, osv, inv, target_root="target"):
    found = {}

    # Inventory (inventory.py): binaries, WASM, archives, scripts, entry points without a JS
    # extension. Bound to path and SHA-256 of the file, like Semgrep matches to file content.
    for f in inv.get("findings") or []:
        rule, path, sha = f.get("rule"), f.get("path"), f.get("sha256")
        if not (isinstance(rule, str) and rule.startswith("inventory-") and isinstance(path, str)
                and isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{64}", sha)):
            raise ScanIncomplete(f"inventory entry incomplete: {json.dumps(f)[:200]}")
        found[fp("inventory", rule, path, sha)] = {
            "tool": "inventory", "rule": rule, "severity": "WARNING", "where": path,
            "code": f"{f.get('kind')}, {f.get('size')} Bytes, SHA-256 {sha[:16]}…",
            "file": path, "line": None}

    for r in gd["risks"]:
        f = rel(r.get("file_path"))
        raw = r.get("threat_match") or ""
        digest = file_digest(Path(target_root) / f if f else "")
        key = fp("guarddog", r.get("threat_rule", ""), f, digest, raw)
        # GuardDog reports only threat matches under "risks"; all of them block
        ctx, origin = guarddog_context(Path(target_root) / f, r.get("threat_location"), raw) if f else (None, None)
        put(found, key, {"tool": "guarddog", "rule": r.get("threat_rule"),
                      "severity": r.get("severity"),
                      "where": r.get("threat_location"), "code": excerpt(norm(raw)),
                      "match_sha256": match_digest(raw), "context": ctx, "origin": origin,
                      "file": f, "line": location_line(r.get("threat_location"))})
    gd_errors = gd.get("errors") or {}
    # A GuardDog error affects the whole target: bind it to the target's content
    whole = target_digest(target_root) if gd_errors else ""
    for stage, msg in gd_errors.items():
        key = fp("guarddog-error", stage, whole)
        found[key] = {"tool": "guarddog", "rule": f"scan-error:{stage}", "severity": "WARNING",
                      "where": stage, "code": excerpt(norm(str(msg)))}

    for x in sg["results"]:
        rule = x["check_id"].split(".")[-1]
        f = rel(x["path"])
        raw = src_lines(x)
        key = fp("semgrep", rule, f, file_digest(x["path"]), raw)
        ctx, origin = semgrep_context(x)
        put(found, key, {"tool": "semgrep", "rule": rule, "severity": x["extra"].get("severity"),
                      "where": f"{f}:{x['start']['line']}", "code": excerpt(norm(raw)),
                      "match_sha256": match_digest(raw), "context": ctx, "origin": origin,
                      "file": f, "line": x["start"].get("line")})
    for e in sg.get("errors") or []:
        # e.g. Timeout, Syntax error, PartialParsing, NotScanned (semgrep-coverage.sh):
        # the file was not checked completely
        etype = e.get("type") or ""
        if isinstance(etype, list):
            # PartialParsing comes as ["PartialParsing", [ranges]]; only the name counts
            etype = etype[0] if etype else ""
        etype = str(etype)
        rule = (e.get("rule_id") or "").split(".")[-1]
        f = rel(e.get("path"))
        key = fp("semgrep-error", etype, rule, f, file_digest(e.get("path")))
        label = f"scan-error:{etype}:{rule}" if rule else f"scan-error:{etype}"
        found[key] = {"tool": "semgrep", "rule": label,
                      "severity": "WARNING", "where": f, "code": excerpt(norm(e.get("message")))}

    for res in osv["results"]:
        for pkg in res.get("packages", []):
            name = pkg["package"]["name"]; ver = pkg["package"].get("version", "")
            for v in pkg.get("vulnerabilities", []):
                vid = v["id"]
                # MAL-* = known malicious package (OpenSSF), everything else = vulnerability
                key = fp("osv", vid, name, ver)
                found[key] = {"tool": "osv", "rule": vid, "where": f"{name}@{ver}",
                              "severity": "ERROR" if vid.startswith("MAL-") else "INFO"}
    return found


def entry_problem(e, today):
    if not isinstance(e, dict) or not isinstance(e.get("fingerprint"), str):
        return "no fingerprint"
    missing = [k for k in ENTRY_FIELDS if not str(e.get(k) or "").strip()]
    if missing:
        return "missing: " + ", ".join(missing)
    kind = e.get("kind", "false-positive")
    if kind not in KINDS:
        return f"kind must be one of {', '.join(KINDS)}"
    try:
        review_by = datetime.date.fromisoformat(e["review_by"])
    except ValueError:
        return "review_by is not a date (YYYY-MM-DD)"
    if review_by < today:
        return f"expired on {review_by}"
    return None


def load_baseline(path, today):
    """Returns (accepted entries per fingerprint, list of problems). Invalid entries suppress
    nothing."""
    if not Path(path).exists():
        return {}, []
    try:
        entries = json.loads(Path(path).read_text())["accepted"]
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise ScanIncomplete(f"{path}: baseline not readable ({e})")
    accepted, problems = {}, []
    for e in entries:
        problem = entry_problem(e, today)
        if problem:
            problems.append({"fingerprint": e.get("fingerprint") if isinstance(e, dict) else None,
                             "problem": problem})
        else:
            accepted[e["fingerprint"]] = e
    return accepted, problems


FINGERPRINT_PATTERN = re.compile(r"^[0-9a-f]{16}$")


def known_blocking(raw):
    """Fingerprints from KNOWN_BLOCKING; anything invalid gives an empty set."""
    try:
        data = json.loads(raw or "[]")
    except ValueError:
        return set()
    if not isinstance(data, list) or not all(isinstance(x, str) and FINGERPRINT_PATTERN.match(x) for x in data):
        return set()
    return set(data)


def scanned_state_matches(state, source_file):
    """Does the scanned target match the plugin state from watch.py (plugin_state)?
    Release: commit of the tag and, if the API provides one, digest of the ZIP.
    Without a release: HEAD commit."""
    try:
        p = dict(x.split("=", 1) for x in (state or "").split(";"))
        commit = read_source(source_file).get("commit", "")
    except (OSError, ValueError, TypeError):
        return False
    if "asset" in p:
        if commit != p.get("commit"):
            return False
        if p.get("digest") == "-":
            return True
        try:
            sha = (Path(source_file).parent / "sha256.txt").read_text().split()[0]
        except (OSError, IndexError):
            return False
        return p.get("digest") == f"sha256:{sha}"
    return bool(commit) and commit == p.get("head")


def main(pid, gd, sg, osv, inv, base, out, src=None, source_file=None, repo=None, mode=None,
         today=None, target_root="target", known=None):
    today = today or datetime.date.today()
    try:
        found = collect(load_scan(gd, "risks"), load_scan(sg, "results"), load_scan(osv, "results"),
                        load_scan(inv, "findings"), target_root)
        baseline, problems = load_baseline(base, today)
    except ScanIncomplete as e:
        print(f"{pid}: INCOMPLETE: {e}")
        return 2
    if src:
        # Display only: a missing link never fails the scan
        try:
            add_source_links(found, src, read_source(source_file).get("commit"), repo, mode, target_root)
        except Exception as e:
            print(f"{pid}: source links not created ({type(e).__name__}: {e})")

    new = {k: v for k, v in found.items() if k not in baseline}
    blocking = {k: v for k, v in new.items() if v.get("severity") != "INFO"}
    if known is None:
        known = known_blocking(os.environ.get("KNOWN_BLOCKING"))
        if known and not (source_file and scanned_state_matches(os.environ.get("KNOWN_STATE"), source_file)):
            print(f"{pid}: scanned target does not match the state of the reported findings, "
                  "all are reported again")
            known = set()
    already = sorted(set(blocking) & known)
    alerting = {k: v for k, v in blocking.items() if k not in known}

    Path(out).write_text(json.dumps({
        "plugin": pid,
        "version": scanned_version(source_file, mode) if source_file else None,
        "new_blocking": blocking,
        # Already reported for this plugin state: still blocking, no new alert
        "known_blocking": already,
        "new_info": {k: v for k, v in new.items() if k not in blocking},
        "baseline_problems": problems,
        "baseline_stale": sorted(set(baseline) - set(found)),
        "accepted": {k: {**found[k], **{f: baseline[k][f] for f in ENTRY_FIELDS},
                         "kind": baseline[k].get("kind", "false-positive")}
                     for k in sorted(set(baseline) & set(found))},
        "all": found,
        "baseline_candidate": {"accepted": [
            {"fingerprint": k, "reason": "", "owner": "", "review_by": "",
             "rule": v["rule"], "where": v["where"]} for k, v in sorted(found.items())]},
    }, indent=1))

    print(f"{pid}: {len(found)} findings, {len(new)} new, {len(blocking)} blocking"
          + (f" ({len(already)} of them already reported)" if already else ""))
    for p in problems:
        print(f"  INVALID BASELINE ENTRY {p['fingerprint']}: {p['problem']}")
    for k, v in blocking.items():
        label = "KNOWN" if k in known else "NEW"
        print(f"  {label} [{v['tool']}] {v['rule']} @ {v['where']}  {v.get('code','')[:120]}")
    return 1 if alerting else 0


if __name__ == "__main__":
    if len(sys.argv) not in (8, 12):
        sys.exit(__doc__)
    sys.exit(main(*sys.argv[1:]))
