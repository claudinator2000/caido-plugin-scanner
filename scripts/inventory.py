#!/usr/bin/env python3
"""Inventory of the scan target and analysis copies of code Semgrep would otherwise miss.

Usage: inventory.py <target-dir> <inventory.json>

1. Every regular file gets path, size, SHA-256 and a type, detected by content
   (magic bytes with a plausible header), not by extension. Reported for review:
   - inventory-native-binary: ELF, PE, Mach-O (including fat), Java class;
   - inventory-wasm: WebAssembly;
   - inventory-archive: embedded archives (ZIP, GZIP, TAR, 7z, RAR, XZ, bzip2, zstd).
     They are not unpacked; their content is unchecked, even if encrypted;
   - inventory-script: shell, PowerShell, batch, VBScript or Python scripts and
     files with a shebang outside JavaScript;
   - inventory-entrypoint-not-js: an entrypoint in manifest.json without a JS extension
     that Caido runs but that would not be scanned as JavaScript;
   - inventory-uninspected-json: a JSON file too large (MAX_WORKFLOW_JSON) or too deeply
     nested to check for workflow code; a workflow inside it would stay unchecked.
   The findings block (WARNING) and are bound to the file's path and SHA-256;
   a baseline exception applies only to exactly that file.
2. Caido workflows (JSON with graph.nodes) contain JavaScript in nodes such as
   caido/code-js and caido/http-code-js (input "code"). Caido runs it, but Semgrep does
   not check it inside a JSON file. Every file up to MAX_WORKFLOW_JSON is read as JSON
   regardless of extension and content and searched for workflow graphs at any depth.
   Each piece of code is written into the target as
   __workflow_code__/<path of the file>/[graph-<g>/]node-<n>.js and checked there by
   GuardDog and Semgrep like any other JS file. The directory must not already exist in
   the package.

File names and contents are untrusted: details go only to inventory.json; the log shows
only a summary.
"""
import hashlib, json, os, struct, sys
from collections import Counter
from pathlib import Path

DERIVED = "__workflow_code__"
JS_EXTENSIONS = (".js", ".mjs", ".cjs")
SCRIPT_EXTENSIONS = (".sh", ".bash", ".zsh", ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".py")
MAX_WORKFLOW_JSON = 20 * 1024 * 1024
HEAD = 4096
CHUNK = 64 * 1024
RULES = {"native": "inventory-native-binary", "wasm": "inventory-wasm",
         "archive": "inventory-archive", "script": "inventory-script"}


def kind_of(head, size, name):
    """(category, type) from the first bytes; category None for unremarkable files."""
    def u32(fmt, off):
        return struct.unpack_from(fmt, head, off)[0] if len(head) >= off + 4 else None
    if head[:4] == b"\x7fELF" and len(head) >= 7 and head[4] in (1, 2) and head[5] in (1, 2) and head[6] == 1:
        return "native", "elf"
    if head[:2] == b"MZ":
        lfanew = u32("<I", 0x3C)
        if lfanew is not None and lfanew + 4 <= len(head) and head[lfanew:lfanew + 4] == b"PE\0\0":
            return "native", "pe"
        if lfanew is not None and lfanew + 4 > len(head) and lfanew + 4 <= size:
            return "native", "pe"  # header lies beyond the bytes read: do not miss it
    if head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "native", "macho"
    if head[:4] in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
        # Fat Mach-O and Java class share the magic: the architecture count is small,
        # the Java major version is 45 or higher
        second = u32(">I", 4)
        if second is not None and 0 < second < 45:
            return "native", "macho-fat"
        return "native", "java-class"
    if head[:4] == b"\0asm" and u32("<I", 4) == 1:
        return "wasm", "wasm"
    for magic, kind in ((b"PK\x03\x04", "zip"), (b"PK\x05\x06", "zip"), (b"PK\x07\x08", "zip"),
                        (b"\x1f\x8b\x08", "gzip"), (b"7z\xbc\xaf\x27\x1c", "7z"), (b"Rar!\x1a\x07", "rar"),
                        (b"\xfd7zXZ\x00", "xz"), (b"\x28\xb5\x2f\xfd", "zstd")):
        if head.startswith(magic):
            return "archive", kind
    if head[:3] == b"BZh" and head[3:4].isdigit() and head[4:10] == b"1AY&SY":
        return "archive", "bzip2"
    if head[257:262] == b"ustar":
        return "archive", "tar"
    lower = name.lower()
    if head[:2] == b"#!" and not lower.endswith(JS_EXTENSIONS):
        return "script", "shebang"
    if lower.endswith(SCRIPT_EXTENSIONS):
        return "script", lower.rsplit(".", 1)[1]
    return None, None


def file_entry(root, path):
    h = hashlib.sha256()
    size = 0
    head = b""
    with open(path, "rb") as f:
        while chunk := f.read(1024 * 1024):
            if len(head) < HEAD:
                head += chunk[:HEAD - len(head)]
            h.update(chunk)
            size += len(chunk)
    rel = path.relative_to(root).as_posix()
    category, kind = kind_of(head, size, path.name)
    return {"path": rel, "size": size, "sha256": h.hexdigest(), "category": category, "kind": kind}


def entrypoint_findings(root, by_path):
    manifest = root / "manifest.json"
    if not manifest.is_file():
        return []
    try:
        plugins = json.loads(manifest.read_bytes()).get("plugins") or []
    except (ValueError, AttributeError, UnicodeDecodeError, RecursionError):
        return []
    out = []
    for p in plugins if isinstance(plugins, list) else []:
        ref = p.get("entrypoint") if isinstance(p, dict) else None
        if isinstance(ref, str) and not ref.lower().endswith(JS_EXTENSIONS) and ref in by_path:
            entry = by_path[ref]
            out.append({"rule": "inventory-entrypoint-not-js", "path": ref, "sha256": entry["sha256"],
                        "kind": "entrypoint", "size": entry["size"]})
    return out


WHITESPACE = b" \t\r\n"


def first_significant_byte(path):
    """First byte after an optional UTF-8 BOM and whitespace, read in chunks (any amount
    of leading whitespace), or b"" for an empty file."""
    with open(path, "rb") as f:
        chunk = f.read(CHUNK).removeprefix(b"\xef\xbb\xbf")
        while chunk:
            rest = chunk.lstrip(WHITESPACE)
            if rest:
                return rest[:1]
            chunk = f.read(CHUNK)
    return b""


def parse_like_node(data):
    """Read JSON at least as leniently as Node (fs.readFileSync(..., "utf8") and
    JSON.parse), so no workflow that Caido loads slips past Python's stricter parser:
    invalid UTF-8 is replaced instead of rejected, numbers stay text (Python rejects
    integers over 4,300 digits), a UTF-8 BOM is skipped."""
    return json.loads(data.decode("utf-8-sig", errors="replace"), parse_int=str, parse_float=str)


def graphs_in(doc):
    """All workflow graphs (dict with graph.nodes as a list) in the document, iteratively in
    document order: [(label, nodes)]. The top-level graph is labelled None, deeper ones
    (e.g. a list of workflows) graph-1, graph-2, ..."""
    found, stack, counter = [], [(doc, True)], 0
    while stack:
        item, root = stack.pop()
        if isinstance(item, dict):
            graph = item.get("graph")
            if isinstance(graph, dict) and isinstance(graph.get("nodes"), list):
                if root:
                    found.append((None, graph["nodes"]))
                else:
                    counter += 1
                    found.append((f"graph-{counter}", graph["nodes"]))
            children = list(item.values())
        elif isinstance(item, list):
            children = item
        else:
            continue
        stack.extend((child, False) for child in reversed(children))
    return found


def uninspected_finding(f, kind):
    return {"rule": "inventory-uninspected-json", "path": f["path"], "sha256": f["sha256"],
            "kind": kind, "size": f["size"]}


def inspect_file(root, f):
    """(code snippets, finding or None) for one file; see workflow_code."""
    path = root / f["path"]
    if f["size"] > MAX_WORKFLOW_JSON:
        if first_significant_byte(path) in (b"{", b"["):
            return [], uninspected_finding(f, "too-large")
        return [], None
    try:
        doc = parse_like_node(path.read_bytes())
    except RecursionError:
        return [], uninspected_finding(f, "too-deep")
    except ValueError:
        return [], None  # not JSON: Caido does not load a workflow from it either
    out = []
    for label, nodes in graphs_in(doc):
        for index, node in enumerate(nodes):
            inputs = node.get("inputs") if isinstance(node, dict) else None
            first = True
            for position, inp in enumerate(inputs if isinstance(inputs, list) else []):
                if not isinstance(inp, dict):
                    continue
                value = inp.get("value")
                if inp.get("alias") == "code" and isinstance(value, dict) and isinstance(value.get("data"), str):
                    # First code input: node-<n>.js; further ones in the same node carry the
                    # input index so each piece of code gets its own file
                    name = f"node-{index}.js" if first else f"node-{index}-input-{position}.js"
                    first = False
                    out.append((f["path"], label, index, name, value["data"]))
    return out, None


def workflow_code(root, files):
    """([(path of the file, graph label, node index, file name, code)], [findings for
    uninspectable files]). Every file up to MAX_WORKFLOW_JSON is read as JSON, regardless of
    extension and content: workflows that plugin code loads at runtime can have any name.
    Larger files that start with { or [ after whitespace, and files nested too deeply,
    are reported as uninspectable. An unexpected error on one file also becomes a finding
    (inspection-error) and does not stop the check of the others."""
    out, uninspected = [], []
    for f in files:
        try:
            snippets, finding = inspect_file(root, f)
        except Exception:
            snippets, finding = [], uninspected_finding(f, "inspection-error")
        out += snippets
        if finding:
            uninspected.append(finding)
    return out, uninspected


def main(target, out_file):
    root = Path(target)
    if (root / DERIVED).exists():
        print(f"ERROR: {DERIVED}/ already exists in the package")
        return 1
    files = sorted((file_entry(root, p) for p in root.rglob("*") if p.is_file() and not p.is_symlink()),
                   key=lambda e: e["path"])
    by_path = {f["path"]: f for f in files}
    findings = [{"rule": RULES[f["category"]], "path": f["path"], "sha256": f["sha256"],
                 "kind": f["kind"], "size": f["size"]} for f in files if f["category"]]
    findings += entrypoint_findings(root, by_path)

    extracted, write_failed = [], set()
    snippets, uninspected = workflow_code(root, files)
    findings += uninspected
    for rel, label, index, name, code in snippets:
        dest = root / DERIVED / rel / (label or "") / name
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
            with os.fdopen(fd, "w", encoding="utf-8", errors="surrogatepass") as w:
                w.write(code)
        except OSError:
            # copy not writable: the code would stay unchecked, so report it as a finding
            if rel not in write_failed:
                write_failed.add(rel)
                findings.append(uninspected_finding(by_path[rel], "write-error"))
            continue
        extracted.append({"source": rel, "graph": label, "node": index, "path": dest.relative_to(root).as_posix()})

    Path(out_file).write_text(json.dumps({"files": files, "findings": findings,
                                          "workflow_code": extracted}, indent=1))
    kinds = Counter(f["kind"] for f in files if f["kind"])
    print(f"Inventory: {len(files)} files, {len(findings)} for review "
          f"({', '.join(f'{k}: {n}' for k, n in sorted(kinds.items())) or 'no notable types'}), "
          f"{len(extracted)} workflow code nodes as JS copies")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    sys.exit(main(*sys.argv[1:3]))
