#!/usr/bin/env python3
"""Combines the reports of a scan run into a Markdown overview and collects the baseline
templates of all plugins.

Usage: summary.py <reports-dir> <plugins.json> <output.md> <templates-dir>
                  [<scanned.json> <report-cache-dir>]

- <reports-dir>/report-<id>/report.json: output of findings.py per plugin
  (missing when the scan was incomplete or aborted earlier)
- <plugins.json>: all plugins the overview shows
- <scanned.json>: the plugins scanned in this run (matrix from scan.yml); without it, all
  count as scanned
- <report-cache-dir>/<id>.json: last verified report of the other plugins
  (watch.py cache_reports), with date and run
- <output.md>: overview for the summary page of the workflow run
- <templates-dir>/<id>.json: baseline_candidate per plugin scanned in this run

A plugin scanned in this run without a report shows as "no report", never with an older
result from the cache.

Findings contain text from untrusted plugin code (paths, code excerpts). All such text is
HTML-escaped and stripped of Markdown control characters before it enters the overview.
"""
import html, json, re, sys
from collections import Counter
from pathlib import Path
from urllib.parse import quote

ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
REPO_PATTERN = re.compile(r"^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$")
# GitHub limits the summary of one step to 1 MiB
DEFAULT_LIMIT = 1_000_000
MAX_FINDINGS_PER_PLUGIN = 50
MAX_CODE = 200
MAX_CONTEXT = 400

# Per rule: what it detects, when it is typically a false positive, and what makes it real
RULE_HELP = {
    "caido-hardcoded-callback-url": (
        "A hard-coded external host is stored as a callback/webhook/OAST address; plugins put such addresses into requests so the scanned target contacts them.",
        "the address is only a default the user is told about and can change, and it belongs to a known OAST service.",
        "an unknown host the user never sees, or request data is added to it (see caido-request-data-to-callback-url)."),
    "caido-request-data-to-callback-url": (
        "Request data (host, URL, headers or body) is built into a callback/OAST URL; the target then sends it to that host (second-order exfiltration).",
        "the callback host is chosen by the user and only an ID or the tested host goes into the path.",
        "the callback host is fixed in the code, or headers/bodies (cookies, tokens) go into the URL."),
    "caido-traffic-to-network": (
        "Data from Caido event handlers, sdk.requests/findings/env or process.env flows into fetch, sendBeacon or a WebSocket.",
        "the target is the local Caido API or a service the user configured (webhook, OAST, AI provider).",
        "request/response content goes to a hard-coded third-party address, especially without a visible setting."),
    "caido-backend-dangerous-module": (
        "The backend loads child_process or net.",
        "the plugin visibly starts its own tool (binary, the user's shell commands) or only listens on 127.0.0.1.",
        "a process start or connection unrelated to the plugin's purpose, fixed commands with downloads (curl | sh), binding to 0.0.0.0."),
    "caido-hardcoded-external-url": (
        "Hard-coded external URL.", "standards, documentation links, placeholders, services matching the purpose.",
        "an unknown domain or IP that is called at runtime."),
    "obf-decode-into-call": (
        "The result of atob/Base64/fromCharCode/reversed strings ends up in a call, a property access or as code/URL.",
        "Base64 helpers (atob → Uint8Array), key code tables, hex/JWT tools, libraries (YAML, node-forge, diff).",
        "the decoded value becomes a URL, a function name (globalThis[decoded]) or executed code."),
    "obf-dynamic-code-exec": (
        "eval, new Function or setTimeout with a string.",
        "lodash `Function(\"return this\")`, feature tests (pdf.js), code generators (ajv), scripts written by the user.",
        "the executed string comes from the network, a decoding step or untrusted data."),
    "obf-dynamic-global-access": (
        "Dynamic access to globalThis/window/navigator with a non-literal key.",
        "Symbol.for keys (Vercel/SDKs), entropy collection (node-forge), polyfills.",
        "the key is built from decoded or concatenated strings (e.g. \"fe\"+\"tch\")."),
    "obf-dynamic-require-import": (
        "require/import with a variable argument.", "worker or plugin loaders with paths from the plugin's own package.",
        "the module name/URL comes from the network or a decoding step."),
    "obf-tool-signature": (
        "Signature of javascript-obfuscator (_0x identifiers).", "rare; a few libraries use _0x names.",
        "many _0x identifiers, string array rotation: deliberately obfuscated code."),
    "threat-network-exfiltration": (
        "GuardDog: data exfiltration patterns (webhook/paste services).",
        "OAST or notification feature of the plugin, payload lists, placeholders.",
        "data is sent to such services without user configuration."),
    "threat-network-outbound-shady-links": (
        "GuardDog: connections to frequently abused domains (IP services, webhooks, storage).",
        "domain lists, payload data, placeholders, the plugin's purpose.", "an actual call without a recognizable purpose."),
    "threat-process-download-exec": (
        "GuardDog: download and execution (curl | sh, exec, requests.get).",
        "help texts, RegExp.exec, Caido SDK sdk.requests.get.", "the code downloads something and runs it."),
    "threat-filesystem-read": (
        "GuardDog: access to sensitive files (/etc/passwd, SSH keys, browser profiles).",
        "pentest payloads and example texts.", "actually reading such files and passing them on."),
    "threat-runtime-environment-read": (
        "GuardDog: reading environment variables.", "configuration and debug switches.",
        "tokens/keys from the environment are sent out."),
    "threat-runtime-keylogging": (
        "GuardDog: keyboard/input capture.", "word lists, help texts, code generators.",
        "input is recorded and passed on."),
    "threat-process-cryptomining": (
        "GuardDog: mining signatures.", "chance matches in Base64 blobs, `nonce`.", "mining pool addresses, worker logic."),
    "threat-runtime-obfuscation": (
        "GuardDog: unusual escape/Unicode sequences.", "Unicode tables in libraries, translations.",
        "long escape sequences that are decoded and executed at runtime."),
    "threat-runtime-obfuscation-base64exec": (
        "GuardDog: Base64 decoding close to execution.", "Base64 helpers, parsers, regex lists.",
        "the decoded content is executed."),
    "threat-runtime-obfuscation-unicode": (
        "GuardDog: mixed scripts (homoglyphs).", "HTML entity tables.", "identifiers with confusable characters."),
    "scan-error": (
        "Semgrep or GuardDog did not check this file completely.",
        "parser quirks in library code that the fallback scan cannot resolve either.",
        "the unchecked part contains plugin code; review it by hand."),
    "caido-secret-in-url": (
        "A licence key, token, secret or password is sent as a URL parameter; the URL ends up in server and proxy logs.",
        "the value is a short-lived session or poll secret for a service the user chose (e.g. an OAST server).",
        "long-lived credentials (licence, API key) go to a hard-coded third-party address."),
    "caido-make-executable": (
        "The plugin makes a file executable (chmod); typical for downloaded programs (download-to-execute).",
        "the plugin installs a documented tool from its official source and verifies a checksum or signature.",
        "the server decides where the program comes from, no checksum/signature, or unrelated to the plugin's purpose."),
    "caido-dynamic-shell-command": (
        "Shell command from variable text: spawn/execFile with shell: true, or exec/execSync without a fixed command.",
        "command and arguments come only from fixed values or are escaped safely before the shell.",
        "values from configuration, requests or the network reach the shell: command injection or downloaded commands."),
    "inventory-native-binary": (
        "The file is a native program (ELF, PE, Mach-O) or Java bytecode, detected by content, not by extension.",
        "the plugin visibly ships its own documented tool (source and build traceable).",
        "a binary unrelated to the purpose, with a misleading extension (e.g. .js, .png) or without traceable origin. Its content is not analyzed."),
    "inventory-wasm": (
        "The file is WebAssembly; its code is not analyzed.",
        "a known library (e.g. parser, compressor) with traceable origin.",
        "WASM without a recognizable source or with a misleading extension."),
    "inventory-archive": (
        "The package contains another archive (ZIP, GZIP, TAR, 7z, RAR, XZ, bzip2, zstd); it is not extracted and its content is unchecked.",
        "sample data or templates whose content fits the purpose (extract and inspect by hand).",
        "an archive with code or binaries that is extracted at runtime, encrypted or with a misleading extension."),
    "inventory-script": (
        "Shell, PowerShell, batch, VBScript or Python script, or a file with a shebang outside JavaScript; the rules only check JavaScript.",
        "a build or helper script that only lives in the source and is not executed.",
        "a script in the shipped package that the plugin starts, especially with downloads or system changes."),
    "inventory-uninspected-json": (
        "A JSON file too large or too deeply nested to check for workflow code (JavaScript in Caido workflows).",
        "a large data file without graph/nodes (inspect by hand).",
        "a workflow with code nodes that escapes the check this way."),
    "inventory-entrypoint-not-js": (
        "manifest.json names an entry point without a JS extension; Caido runs it, the scan does not check it as JavaScript.",
        "hardly ever: all entry points in the store have a JS extension.",
        "code under an inconspicuous extension to evade the scan."),
}


def rule_help(rule):
    key = "scan-error" if str(rule).startswith("scan-error") else rule
    return RULE_HELP.get(key)


# HTML special characters plus Markdown control characters (tables, code, links, emphasis)
ESCAPES = {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
           "|": "&#124;", "`": "&#96;", "[": "&#91;", "]": "&#93;", "*": "&#42;",
           "_": "&#95;", "#": "&#35;", "\\": "&#92;", "~": "&#126;"}


def esc(text, limit=None):
    """Embed untrusted text safely in Markdown/HTML: one line, no tags, no links, no table
    or code delimiters."""
    text = str(text if text is not None else "")
    text = re.sub(r"[\r\n\t]+", " ", text)
    if limit and len(text) > limit:
        text = text[:limit] + "…"
    # One pass over the original characters, so no entity is replaced twice
    return "".join(ESCAPES.get(c, c) for c in text)


def load_plugins(path):
    plugins = json.loads(Path(path).read_text())
    for p in plugins:
        if not isinstance(p.get("id"), str) or not ID_PATTERN.match(p["id"]):
            raise ValueError(f"invalid plugin id: {p.get('id')!r}")
        if not isinstance(p.get("repo"), str) or not REPO_PATTERN.match(p["repo"]):
            raise ValueError(f"invalid repo for {p['id']}: {p.get('repo')!r}")
    return plugins


def load_report(reports_dir, pid):
    f = Path(reports_dir) / f"report-{pid}" / "report.json"
    if not f.is_file():
        return None
    return json.loads(f.read_text())


MAX_RULES_IN_TABLE = 8
MAX_ALSO = 10


def rule_counts(findings):
    counts = Counter(v.get("rule") for v in findings.values()).most_common()
    shown = [f"{esc(r)} ×{n}" if n > 1 else esc(r) for r, n in counts[:MAX_RULES_IN_TABLE]]
    if len(counts) > MAX_RULES_IN_TABLE:
        shown.append(f"… {len(counts) - MAX_RULES_IN_TABLE} more")
    return ", ".join(shown)


def esc_block(text, limit=None):
    """Like esc(), but line breaks are kept (for <pre>). Blank lines are removed so the HTML
    block does not end and untrusted text is not read as Markdown."""
    text = str(text if text is not None else "").replace("\r", "").replace("\t", "  ")
    text = re.sub(r"\n\s*\n", "\n", text)
    if limit and len(text) > limit:
        text = text[:limit] + "…"
    return "".join(ESCAPES.get(c, c) for c in text)


def shared_key(v):
    # Complete match instead of the shortened excerpt; older reports without digest: excerpt
    return (v.get("rule"), v.get("match_sha256") or v.get("code"))


def source_link(v):
    """Link into the source at the scanned commit (findings.py add_source_links), otherwise None."""
    src = v.get("source")
    if not isinstance(src, dict) or not str(src.get("url", "")).startswith("https://github.com/"):
        return None
    line = src.get("line")
    label = f"{src.get('path')}:{line}" if line else str(src.get("path"))
    # Attribute escaping only: findings.py builds the URL from a checked repository, commit
    # and URL-encoded path; lines inside HTML blocks need no Markdown escapes (e.g. for #)
    return f'<a href="{html.escape(src["url"], quote=True)}"><code>{esc(label, MAX_CODE)}</code></a>'


NPM_NAME = re.compile(r"^(@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$")
NPM_VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+-]*$")


def npm_link(name):
    """Package page on npmjs.com for "package@version" (from library_of in findings.py), otherwise None."""
    name = str(name or "")
    pkg, _, version = name.rpartition("@") if name.rfind("@") > 0 else (name, "", "")
    if not NPM_NAME.match(pkg) or (version and not NPM_VERSION.match(version)):
        return None
    url = f"https://www.npmjs.com/package/{pkg}" + (f"/v/{version}" if version else "")
    return f'<a href="{html.escape(url, quote=True)}"><code>{esc(name, MAX_CODE)}</code></a>'


def origin_line(v):
    origin, link = v.get("origin"), source_link(v)
    if origin and origin.get("kind") == "library":
        label = origin.get("name") or origin.get("path")
        npm = npm_link(origin.get("name"))
        shown = npm or f"<code>{esc(label, MAX_CODE)}</code>"
        return (f"<br>Origin: library {shown} (per path comment in the bundle, unverified;"
                " library code is not in the plugin's repository, so there is no line link)")
    if origin and link:
        exact = "" if (v.get("source") or {}).get("line") else ", line not unique: file only"
        return (f"<br>Origin: plugin code {link} (path comment in the bundle; file found in the"
                f" repository at the scanned commit{exact})")
    if origin:
        return (f"<br>Origin: plugin code <code>{esc(origin.get('path'), MAX_CODE)}</code>"
                " (per path comment in the bundle; file not found uniquely in the repository)")
    if link and (v.get("source") or {}).get("how") == "search":
        return f"<br>Source: {link} (found by text search in the repository at the scanned commit, unique)"
    if link:
        return f"<br>Source: {link}"
    if v.get("context") and str(v.get("where", "")).split(":")[0].endswith((".js", ".mjs", ".cjs")):
        return ("<br>Source: only in the built bundle; no file in the repository matches uniquely"
                " (usually bundled library code without a path comment). See the code below.")
    return ""


def finding_item(pid, key, v, shared):
    parts = [f"<li><code>{esc(v.get('tool'))}</code> <b>{esc(v.get('rule'))}</b>"
             f" @ <code>{esc(v.get('where'))}</code>"]
    parts.append(origin_line(v))
    for extra in (v.get("also") or [])[:MAX_ALSO]:
        parts.append(f"<br>Same code also @ <code>{esc(extra.get('where'))}</code>"
                     + origin_line(extra).replace("<br>", " – ", 1))
    if len(v.get("also") or []) > MAX_ALSO:
        parts.append(f"<br>… {len(v['also']) - MAX_ALSO} more locations in the report")
    help_ = rule_help(v.get("rule"))
    if help_:
        parts.append(f"<br><i>Detects:</i> {esc(help_[0])} <i>False positive when:</i> {esc(help_[1])}"
                     f" <i>Real when:</i> {esc(help_[2])}")
    else:
        parts.append("<br><i>No explanation available for this rule.</i>")
    others = [p for p in shared.get(shared_key(v), []) if p != pid]
    if others:
        shown = ", ".join(esc(p) for p in others[:8]) + (" …" if len(others) > 8 else "")
        parts.append(f"<br>Same match in {len(others)} other plugins: {shown}")
    code = code_block(v)
    if code:
        parts.append(code if code.startswith("<pre>") else "<br>" + code)
    entry = {"fingerprint": key, "reason": "", "owner": "", "review_by": "",
             "rule": v.get("rule"), "where": v.get("where")}
    parts.append("<details><summary>Baseline entry</summary><pre>"
                 + esc_block(json.dumps(entry, indent=1, ensure_ascii=False)) + "</pre></details>")
    parts.append("</li>")
    return "".join(parts)


def blocking_block(pid, rep, shared, max_items):
    """Collapsible list of a plugin's blocking findings (a table cell)."""
    items = list(rep["new_blocking"].items())
    known = set(rep.get("known_blocking") or [])
    new = sum(1 for k, _ in items if k not in known)
    label = (f"<b>{len(items)} blocking</b>" + (f" ({new} new)" if known and new else "")
             + f": {rule_counts(rep['new_blocking'])}")
    if max_items == 0:
        return f"{label} (details in artifact <code>report-{esc(pid)}</code>)"
    lines = [f"<details><summary>{label}</summary>", "<ul>"]
    for key, v in items[:max_items]:
        lines.append(finding_item(pid, key, v, shared))
    if len(items) > max_items:
        lines.append(f"<li>… {len(items) - max_items} more in the artifact "
                     f"<code>report-{esc(pid)}</code></li>")
    lines += ["</ul>", "</details>"]
    return "\n".join(lines)


def code_block(v):
    """Code before, in (bold) and after the match; without context, the shortened excerpt."""
    ctx = v.get("context")
    if ctx:
        return ("<pre>" + esc_block(ctx.get("before", ""))
                + "<b>" + esc_block(ctx.get("match", ""), MAX_CONTEXT) + "</b>"
                + esc_block(ctx.get("after", "")) + "</pre>")
    if v.get("code"):
        return f"<code>{esc(v.get('code'), MAX_CODE)}</code>"
    return ""


def accepted_block(rep, detailed):
    items = list((rep.get("accepted") or {}).values())
    if not detailed:
        return f"{len(items)} accepted"
    lines = [f"<details><summary>{len(items)} accepted</summary>", "<ul>"]
    for v in items:
        code = code_block(v)
        lines.append(f"<li><code>{esc(v.get('tool'))}</code> <b>{esc(v.get('rule'))}</b>"
                     f" @ <code>{esc(v.get('where'))}</code>{origin_line(v)}"
                     f"<br><i>Reason:</i> {esc(v.get('reason'))}"
                     f"<br><i>Owner:</i> {esc(v.get('owner'))}"
                     f" · <i>review by:</i> {esc(v.get('review_by'))}"
                     + (f"<details><summary>Code</summary>{code}</details>" if code else "")
                     + "</li>")
    lines += ["</ul>", "</details>"]
    return "\n".join(lines)


def problems_block(rep):
    problems = rep.get("baseline_problems") or []
    lines = [f"<details><summary>{len(problems)} invalid baseline entries</summary>", "<ul>"]
    for pr in problems:
        lines.append(f"<li><code>{esc(pr.get('fingerprint'))}</code>: {esc(pr.get('problem'))}</li>")
    lines += ["</ul>", "</details>"]
    return "\n".join(lines)


DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")
RUN_URL_PATTERN = re.compile(r"^https://github\.com/[A-Za-z0-9-]+/[A-Za-z0-9._-]+/actions/runs/\d+$")


def load_cached(cache_dir, pid):
    if not cache_dir:
        return None
    f = Path(cache_dir) / f"{pid}.json"
    try:
        return json.loads(f.read_text()) if f.is_file() else None
    except ValueError:
        return None


def alarming(rep):
    """Blocking findings reported for the first time in this scan."""
    known = set(rep.get("known_blocking") or [])
    return [k for k in rep["new_blocking"] if k not in known]


def stand(rep, fresh):
    if fresh:
        return "this run"
    date = str(rep.get("scanned_at") or "")
    date = date if DATE_PATTERN.match(date) else "earlier"
    url = str(rep.get("run_url") or "")
    return f'<a href="{url}">{date}</a>' if RUN_URL_PATTERN.match(url) else date


TAG_PATTERN = re.compile(r"^[A-Za-z0-9._+-]{1,128}$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")


def version_cell(repo, rep):
    """Scanned release tag (linked to the release) or commit (linked to the tree)."""
    v = rep.get("version") if isinstance(rep.get("version"), dict) else {}
    tag, commit = str(v.get("tag") or ""), str(v.get("commit") or "")
    if TAG_PATTERN.match(tag):
        return f'<a href="https://github.com/{repo}/releases/tag/{quote(tag)}">{esc(tag)}</a>'
    if COMMIT_PATTERN.match(commit):
        return f'<a href="https://github.com/{repo}/tree/{commit}"><code>{commit[:7]}</code></a>'
    return "–"


def main(reports_dir, plugins_file, out, candidates_dir, limit=DEFAULT_LIMIT, selected_file=None, cache_dir=None):
    plugins = load_plugins(plugins_file)
    selected = ({p.get("id") for p in json.loads(Path(selected_file).read_text())} if selected_file
                else {p["id"] for p in plugins})
    rows = []
    for p in plugins:
        fresh = p["id"] in selected
        rep = load_report(reports_dir, p["id"]) if fresh else load_cached(cache_dir, p["id"])
        blocking = len(rep["new_blocking"]) if rep else None
        rows.append((p, rep, blocking, fresh))

    # No report first, then newly blocked, then by number of blocking findings, then alphabetically
    rows.sort(key=lambda r: (r[1] is not None, not (r[1] and alarming(r[1])), -(r[2] or 0), r[0]["id"]))

    Path(candidates_dir).mkdir(parents=True, exist_ok=True)
    for p, rep, _, fresh in rows:
        if rep and fresh and rep.get("baseline_candidate"):
            (Path(candidates_dir) / f"{p['id']}.json").write_text(
                json.dumps(rep["baseline_candidate"], indent=1) + "\n")

    missing = sum(1 for _, rep, _, _ in rows if rep is None)
    bad = sum(1 for _, rep, b, _ in rows if rep is not None and b)
    alarms = sum(1 for _, rep, b, fresh in rows if rep is not None and b and fresh and alarming(rep))
    ok = len(rows) - missing - bad
    scanned = sum(1 for r in rows if r[3])

    head = "\n".join([
        "## Caido plugin scan",
        "",
        f"**{len(rows)} plugin{'' if len(rows) == 1 else 's'}** ({scanned} scanned in this run, the others with their last "
        f"result): {ok} without blocking findings · {bad} blocked, {alarms} of them with a new "
        f"finding in this run · {missing} without a report (scan incomplete, aborted or never "
        "run, see the job log)",
        "",
        "A run fails only on new findings: a finding already reported for the same plugin state "
        "stays blocked here (🔴 reported) but no longer causes a red run or an email. An update "
        "of the plugin reports all its findings again.",
        "",
        "Baseline templates of the plugins scanned in this run: artifact `baseline-candidates` "
        "(one file per plugin). Raw data per plugin: artifact `report-<id>` of the respective run.",
        "",
    ])

    # The same match (rule + complete code) in several plugins hints at a shared library
    shared = {}
    for p, rep, b, _ in rows:
        for v in (rep or {}).get("new_blocking", {}).values() if b else []:
            ids = shared.setdefault(shared_key(v), [])
            if p["id"] not in ids:
                ids.append(p["id"])

    def table(accepted_details, max_items):
        # HTML instead of a Markdown table: cells with multi-line, collapsible findings.
        # No blank lines inside the block, otherwise it ends for the Markdown parser.
        out = ["<table>", "<thead><tr><th>Plugin</th><th>Version</th><th>Status</th><th>Scanned</th><th>Blocking</th>"
               "<th>Accepted</th><th>Info</th><th>Baseline problems</th><th>Findings</th></tr></thead>",
               "<tbody>"]
        for p, rep, b, fresh in rows:
            link = f'<a href="https://github.com/{p["repo"]}">{esc(p["id"])}</a>'
            if rep is None:
                why = "no report" if fresh else "no result yet"
                out.append(f"<tr><td>{link}</td><td>–</td><td>⚪ {why}</td><td>{'this run' if fresh else '–'}</td>"
                           "<td>–</td><td>–</td><td>–</td><td>–</td><td></td></tr>")
                continue
            if not b:
                status = "🟢 ok"
            elif alarming(rep) and fresh:
                status = "🔴 new"
            else:
                status = "🔴 reported"
            cells = []
            if b:
                cells.append(blocking_block(p["id"], rep, shared, max_items))
            if rep.get("accepted"):
                cells.append(accepted_block(rep, accepted_details))
            if rep.get("baseline_problems"):
                cells.append(problems_block(rep))
            out.append(f"<tr><td>{link}</td><td>{version_cell(p['repo'], rep)}</td><td>{status}</td>"
                       f"<td>{stand(rep, fresh)}</td><td>{b}</td>"
                       f"<td>{len(rep.get('accepted') or {})}</td><td>{len(rep.get('new_info') or {})}</td>"
                       f"<td>{len(rep.get('baseline_problems') or [])}</td><td>{chr(10).join(cells)}</td></tr>")
        out += ["</tbody>", "</table>", ""]
        return "\n".join(out)

    # If the overview exceeds the limit: first only count accepted findings, then show
    # fewer blocking findings per plugin
    note = "\n_… shortened: complete findings in the artifact `report-<id>` of the respective plugin._\n"
    levels = [(True, MAX_FINDINGS_PER_PLUGIN), (False, MAX_FINDINGS_PER_PLUGIN), (False, 10), (False, 3),
              (False, 1), (False, 0)]
    for i, (acc, n) in enumerate(levels):
        text = head + "\n" + table(acc, n) + (note if i else "")
        if len(text.encode()) <= limit:
            break
    Path(out).write_text(text + "\n")
    return 0


if __name__ == "__main__":
    if len(sys.argv) not in (5, 7):
        sys.exit(__doc__)
    a = sys.argv[1:]
    sys.exit(main(*a[:4], selected_file=a[4] if len(a) == 6 else None, cache_dir=a[5] if len(a) == 6 else None))
