#!/usr/bin/env python3
"""Fallback scan for JavaScript files that Semgrep does not parse completely.

Usage: semgrep_fallback.py <target-dir> <semgrep.json>   (the file is extended in place)

Two cases: "Syntax error" (the whole file was not checked; for large bundles this also
happens without a single broken part) and "PartialParsing" (Semgrep skipped parts).
Causes in the store bundles: the identifier `as` (e.g. `class as {}`) and "<!--"/"-->" in
regex literals (e.g. /^<!--/ in Markdown parsers), which Semgrep's lexer takes for
HTML-style comments. For every affected .js/.mjs/.cjs file:

1. scripts/js-split/split.mjs (acorn) returns blocks of consecutive top-level
   statements, the `as` identifiers and the markers in literals.
2. Stage 1: a copy of the whole file in which `as` becomes `ª` and "<!--"/"-->" in
   literals become "<!__"/"__>" (same byte length, lines and offsets are kept).
   The rules do not depend on these names and regex contents; code excerpts in the
   report come from the original file.
3. Stage 2: one masked copy per block (everything outside the block becomes spaces,
   line breaks are kept), with the same replacements.
4. Matches from both stages are merged and get the original file's path back.
   Both stages always run: in stage 1 taint rules see data flows across block boundaries,
   but in very large top-level code they silently lose data flows they find within a
   block (measured on a store bundle: 4 matches only in stage 2).

The original errors are removed only if one stage checked the file without syntax or
PartialParsing errors; otherwise they stay, together with the errors from stage 2
(the gate blocks). If acorn cannot parse the file, the error stays as well.
"""
import json, os, shutil, subprocess, sys, tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
JS_EXTENSIONS = (".js", ".mjs", ".cjs")
MAX_BLOCK_BYTES = 150_000


def shown(path):
    """Path for log output: as a JSON string, so line breaks in untrusted file names
    create no new log line (and no workflow command)."""
    return json.dumps(str(path), ensure_ascii=True)


def error_type(e):
    t = e.get("type") or ""
    return t[0] if isinstance(t, list) and t else str(t)


FAILING = ("Syntax error", "PartialParsing")
RENAMED = "ª".encode()  # same byte length as b"as"
NEUTRAL = {b"<!--": b"<!__", b"-->": b"__>"}


def mask(data, start, end, renames=(), neutral=()):
    """Copy of data in which everything outside [start, end) becomes spaces
    (line breaks are kept so lines and offsets stay the same). Ranges from renames
    inside the block are replaced by RENAMED, markers from neutral by their
    same-length counterparts from NEUTRAL."""
    table = bytes(b if b in (10, 13) else 32 for b in range(256))
    block = bytearray(data[start:end])
    for r_start, r_end in renames:
        if start <= r_start and r_end <= end and r_end - r_start == len(RENAMED):
            block[r_start - start : r_end - start] = RENAMED
    for n_start, n_end in neutral:
        replacement = NEUTRAL.get(bytes(data[n_start:n_end]))
        if replacement and start <= n_start and n_end <= end:
            block[n_start - start : n_end - start] = replacement
    return data[:start].translate(table) + bytes(block) + data[end:].translate(table)


def plausible(split, data):
    """Use the splitter output only if it fits the file: every block lies inside the
    file and contains code, every rename hits exactly b"as", every marker exactly
    "<!--" or "-->". Otherwise the scan copy would be empty or wrong, and an empty scan
    would count as complete."""
    blocks, renames = split.get("blocks") or [], split.get("renames") or []
    neutral = split.get("neutral") or []
    if not blocks:
        return False
    for start, end in blocks:
        if not (0 <= start < end <= len(data)) or not data[start:end].strip():
            return False
    return all(data[s:e] == b"as" for s, e in renames) and all(data[s:e] in NEUTRAL for s, e in neutral)


def split_blocks(path):
    proc = subprocess.run(["node", str(HERE / "js-split" / "split.mjs"), str(path), str(MAX_BLOCK_BYTES)],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        return None
    return json.loads(proc.stdout)


def run_semgrep(directory, out):
    """Semgrep on a directory with the same settings as semgrep-scan.sh."""
    (Path(directory) / ".semgrepignore").write_text("")
    subprocess.run(
        ["uvx", f"semgrep=={os.environ['SEMGREP_VERSION']}", "scan", "--metrics=off",
         "--timeout", os.environ.get("SEMGREP_RULE_TIMEOUT", "120"), "--timeout-threshold", "0",
         "--max-target-bytes", "0", "--disable-nosem", "--no-git-ignore",
         "--project-root", str(directory), "--config", str(HERE.parent / "rules"),
         str(directory), "--json", "--output", str(out)],
        check=True, stdout=subprocess.DEVNULL)
    return json.loads(Path(out).read_text())


def scan_copies(runner, work, plan, splits):
    """Writes a masked copy with replacements for every range in plan ({original path:
    [(start, end), ...]}), scans all of them in one run and maps the paths back to the
    originals. Returns (matches, errors, originals with syntax/PartialParsing errors)."""
    work.mkdir()
    chunks = {}  # copy -> original path
    for original, ranges in plan.items():
        split, data = splits[original]
        for start, end in ranges:
            copy = work / f"{len(chunks):04d}" / Path(original).name
            copy.parent.mkdir()
            copy.write_bytes(mask(data, start, end, split.get("renames") or [], split.get("neutral") or []))
            chunks[str(copy)] = original
    result = runner(work, work.with_suffix(".json"))

    def original_of(path):
        # Semgrep reports paths as they were passed in (absolute under work)
        return chunks.get(path) or chunks.get(str(Path(path).resolve()))

    results, errors, failing = [], [], set()
    for x in result.get("results", []):
        x["path"] = original_of(x["path"])
        if x["path"] is not None:
            results.append(x)
    for e in result.get("errors") or []:
        orig = original_of(e.get("path", "")) if e.get("path") else None
        if orig is None:
            continue
        e["path"] = orig
        if error_type(e) in FAILING:
            failing.add(orig)
            e["message"] = f"Fallback scan: still not completely parseable. {e.get('message', '')}"
        errors.append(e)
    return results, errors, failing


def main(target, sg_file, runner=run_semgrep, splitter=split_blocks):
    sg = json.loads(Path(sg_file).read_text())
    failed = [e for e in sg.get("errors") or []
              if error_type(e) in FAILING and str(e.get("path", "")).endswith(JS_EXTENSIONS)]
    if not failed:
        return 0

    work = Path(tempfile.mkdtemp(prefix="semgrep-fallback-"))
    try:
        splits = {}
        for original in dict.fromkeys(e["path"] for e in failed):
            split = splitter(original)
            data = Path(original).read_bytes()
            if not split or not plausible(split, data):
                print(f"Fallback scan: {shown(original)} cannot be split, error stays")
                continue
            splits[original] = (split, data)
        if not splits:
            return 0

        # Stage 1: whole file, stage 2: blocks; both with replacements, both always
        whole = {p: [(0, len(d))] for p, (_, d) in splits.items()}
        blocks = {p: [tuple(b) for b in sp["blocks"]] for p, (sp, _) in splits.items()}
        results1, errors1, failing1 = scan_copies(runner, work / "whole", whole, splits)
        results2, errors2, failing2 = scan_copies(runner, work / "blocks", blocks, splits)
        # Matches from both stages are real matches in the original; the same match (rule,
        # file, byte range) from both stages is taken only once
        seen = set()
        for x in results1 + results2:
            key = (x.get("check_id"), x["path"], x["start"].get("offset"), x["end"].get("offset"))
            if key not in seen:
                seen.add(key)
                sg["results"].append(x)
        done = {p for p in splits if p not in failing1 or p not in failing2}
        # Parse errors: files not checked completely keep the original errors plus those
        # of the blocks; for parsed files both are dropped.
        # Other errors (e.g. a rule timeout) from both stages always stay:
        # parsed does not mean checked.
        sg["errors"] = [e for e in sg["errors"] if not (e in failed and e["path"] in done)]
        sg["errors"] += [e for e in errors2 if error_type(e) in FAILING and e["path"] not in done]
        kept = set()
        for e in errors1 + errors2:
            key = (error_type(e), e["path"], e.get("rule_id"))
            if error_type(e) not in FAILING and key not in kept:
                kept.add(key)
                sg["errors"].append(e)
        sg.setdefault("fallback", []).extend(
            {"path": p, "blocks": len(blocks[p]), "whole_file": p not in failing1, "complete": p in done}
            for p in splits)
        Path(sg_file).write_text(json.dumps(sg))
        for p in splits:
            status = "complete" if p in done else "incomplete"
            whole_status = "whole file parseable" if p not in failing1 else "whole file not parseable"
            print(f"Fallback scan: {shown(p)} ({whole_status}) and in {len(blocks[p])} blocks, {status}")
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)
        for stage in ("whole", "blocks"):
            (work / stage).with_suffix(".json").unlink(missing_ok=True)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    sys.exit(main(*sys.argv[1:3]))
