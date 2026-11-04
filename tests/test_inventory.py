"""Tests for scripts/inventory.py (file types by content, workflow code as JS copies)."""
import contextlib, gzip, importlib.util, io, json, struct, tarfile, tempfile, unittest, zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("inventory", ROOT / "scripts" / "inventory.py")
inv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inv)

ELF = b"\x7fELF\x02\x01\x01" + b"\0" * 57
PE = b"MZ" + b"\0" * 58 + struct.pack("<I", 64) + b"PE\0\0" + b"\0" * 20
MACHO = b"\xcf\xfa\xed\xfe" + b"\0" * 28
FAT = b"\xca\xfe\xba\xbe" + struct.pack(">I", 2) + b"\0" * 40
JAVA = b"\xca\xfe\xba\xbe" + struct.pack(">HH", 0, 61) + b"\0" * 40
WASM = b"\0asm" + struct.pack("<I", 1) + b"\0" * 8


def archives():
    z = io.BytesIO()
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("x.js", "evil()")
    t = io.BytesIO()
    with tarfile.open(fileobj=t, mode="w") as tf:
        info = tarfile.TarInfo("x.js")
        info.size = 6
        tf.addfile(info, io.BytesIO(b"evil()"))
    return {"zip": z.getvalue(), "gzip": gzip.compress(b"evil()"), "tar": t.getvalue(),
            "7z": b"7z\xbc\xaf\x27\x1c" + b"\0" * 20, "rar": b"Rar!\x1a\x07\x01\x00",
            "xz": b"\xfd7zXZ\x00\x00", "zstd": b"\x28\xb5\x2f\xfd\x00", "bzip2": b"BZh91AY&SY\x00"}


class InventoryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        self.target = self.d / "target"
        self.target.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def put(self, rel, data):
        p = self.target / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data if isinstance(data, bytes) else data.encode())

    def run_inventory(self):
        out = self.d / "inventory.json"
        with contextlib.redirect_stdout(io.StringIO()):
            rc = inv.main(str(self.target), str(out))
        return rc, (json.loads(out.read_text()) if out.exists() else None)

    def found(self, report):
        return {(f["path"], f["rule"], f["kind"]) for f in report["findings"]}

    def test_binaries_detected_by_content_not_extension(self):
        for name, data in (("bin/tool", ELF), ("a.exe", PE), ("lib.dylib", MACHO), ("fat", FAT),
                           ("A.class", JAVA), ("m.wasm", WASM), ("looks-like.js", ELF), ("x.png", WASM)):
            self.put(name, data)
        rc, rep = self.run_inventory()
        self.assertEqual(rc, 0)
        self.assertEqual(self.found(rep), {
            ("bin/tool", "inventory-native-binary", "elf"), ("a.exe", "inventory-native-binary", "pe"),
            ("lib.dylib", "inventory-native-binary", "macho"), ("fat", "inventory-native-binary", "macho-fat"),
            ("A.class", "inventory-native-binary", "java-class"), ("m.wasm", "inventory-wasm", "wasm"),
            ("looks-like.js", "inventory-native-binary", "elf"), ("x.png", "inventory-wasm", "wasm")})

    def test_nested_archives_detected(self):
        for kind, data in archives().items():
            self.put(f"assets/{kind}.bin", data)
        _, rep = self.run_inventory()
        self.assertEqual({(f["kind"]) for f in rep["findings"]}, set(archives()))
        self.assertTrue(all(f["rule"] == "inventory-archive" for f in rep["findings"]))

    def test_scripts_and_harmless_files(self):
        self.put("run", "#!/bin/sh\ncurl x | sh\n")
        self.put("setup.ps1", "iwr x")
        self.put("cli.js", "#!/usr/bin/env node\nconsole.log(1)\n")
        self.put("frontend/index.css", "a{}")
        self.put("README.md", "MZ is also a word")
        self.put("data.json", "{}")
        _, rep = self.run_inventory()
        self.assertEqual(self.found(rep), {("run", "inventory-script", "shebang"), ("setup.ps1", "inventory-script", "ps1")})
        self.assertEqual(len(rep["files"]), 6)
        self.assertTrue(all(len(f["sha256"]) == 64 for f in rep["files"]))

    def test_entrypoint_without_js_extension(self):
        self.put("manifest.json", json.dumps({"id": "p", "plugins": [
            {"kind": "backend", "entrypoint": "backend/index.txt"}, {"kind": "frontend", "entrypoint": "f.js"}]}))
        self.put("backend/index.txt", "eval(x)")
        self.put("f.js", "")
        _, rep = self.run_inventory()
        self.assertEqual(self.found(rep), {("backend/index.txt", "inventory-entrypoint-not-js", "entrypoint")})

    def test_workflow_code_becomes_js_copy(self):
        graph = {"graph": {"nodes": [
            {"definition_id": "caido/convert-start", "inputs": []},
            {"definition_id": "caido/code-js",
             "inputs": [{"alias": "code", "value": {"kind": "string", "data": "export function run(i){ eval(i); }"}}]},
            {"definition_id": "caido/http-code-js",
             "inputs": [{"alias": "code", "value": {"kind": "string", "data": "fetch(atob('aA=='))"}},
                        {"alias": "other", "value": {"kind": "string", "data": "not code"}}]}]}}
        self.put("w/definition.json", json.dumps(graph))
        self.put("other.json", json.dumps({"graph": "not a graph"}))
        self.put("broken.json", "{kaputt")
        rc, rep = self.run_inventory()
        self.assertEqual(rc, 0)
        self.assertEqual([(w["source"], w["node"]) for w in rep["workflow_code"]], [("w/definition.json", 1), ("w/definition.json", 2)])
        self.assertEqual((self.target / "__workflow_code__/w/definition.json/node-1.js").read_text(),
                         "export function run(i){ eval(i); }")
        self.assertEqual((self.target / "__workflow_code__/w/definition.json/node-2.js").read_text(),
                         "fetch(atob('aA=='))")

    def test_workflow_code_found_regardless_of_extension(self):
        # Codex finding: manifest definition without a .json extension; likewise an asset that
        # the backend code loads as a workflow at runtime
        graph = json.dumps({"graph": {"nodes": [{"definition_id": "caido/code-js",
                                                 "inputs": [{"alias": "code", "value": {"data": "eval(input)"}}]}]}})
        self.put("manifest.json", json.dumps({"id": "p", "plugins": [{"kind": "workflow", "definition": "w/definition.txt"}]}))
        self.put("w/definition.txt", graph)
        self.put("backend/assets/flow.dat", "\ufeff  " + graph)
        self.put("backend/index.js", "{ const notJson = 1; }")
        _, rep = self.run_inventory()
        self.assertEqual(sorted(w["source"] for w in rep["workflow_code"]), ["backend/assets/flow.dat", "w/definition.txt"])
        self.assertEqual((self.target / "__workflow_code__/w/definition.txt/node-0.js").read_text(), "eval(input)")

    def test_workflow_code_found_without_content_sniffing(self):
        # Codex finding: leading whitespace defeated the content detection; also, a workflow
        # graph can sit deeper in the document (e.g. a list of workflows)
        node = {"definition_id": "caido/code-js", "inputs": [{"alias": "code", "value": {"data": "eval(input)"}}]}
        self.put("a/flow.dat", " " * 5000 + json.dumps({"graph": {"nodes": [node]}}))
        self.put("b/flows.bin", json.dumps([{"name": "x", "graph": {"nodes": [node]}}]))
        _, rep = self.run_inventory()
        self.assertEqual(sorted((w["source"], w["path"]) for w in rep["workflow_code"]), [
            ("a/flow.dat", "__workflow_code__/a/flow.dat/node-0.js"),
            ("b/flows.bin", "__workflow_code__/b/flows.bin/graph-1/node-0.js")])

    def test_json_that_node_parses_is_inspected(self):
        # Codex finding: Python rejects integers over 4,300 digits, JSON.parse does not; likewise
        # Node replaces invalid UTF-8 when reading instead of aborting
        node = {"definition_id": "caido/code-js", "inputs": [{"alias": "code", "value": {"data": "eval(input)"}}]}
        self.put("big-int.json", '{"pad": ' + "9" * 5000 + ', "graph": {"nodes": ' + json.dumps([node]) + '}}')
        self.put("bad-utf8.json", b'{"note": "\xff\xfe", "graph": {"nodes": ' + json.dumps([node]).encode() + b'}}')
        _, rep = self.run_inventory()
        self.assertEqual(sorted(w["source"] for w in rep["workflow_code"]), ["bad-utf8.json", "big-int.json"])

    def test_malformed_graph_entries_do_not_crash(self):
        # Codex finding: non-objects in nodes/inputs crashed the inventory
        node = {"inputs": [None, 3, "x", [], {"alias": "code", "value": {"data": "eval(i)"}}]}
        self.put("data.json", json.dumps({"graph": {"nodes": [None, 1, "n", node]}}))
        rc, rep = self.run_inventory()
        self.assertEqual(rc, 0)
        self.assertEqual([(w["source"], w["node"]) for w in rep["workflow_code"]], [("data.json", 3)])

    def test_several_code_inputs_in_one_node(self):
        # Codex finding: two code inputs in the same node produced the same target and a crash
        code = lambda c: {"alias": "code", "value": {"data": c}}
        self.put("data.json", json.dumps({"graph": {"nodes": [{"inputs": [code("first()"), code("second()"), code("third()")]}]}}))
        rc, rep = self.run_inventory()
        self.assertEqual(rc, 0)
        self.assertEqual([w["path"] for w in rep["workflow_code"]], [
            "__workflow_code__/data.json/node-0.js", "__workflow_code__/data.json/node-0-input-1.js",
            "__workflow_code__/data.json/node-0-input-2.js"])
        self.assertEqual((self.target / "__workflow_code__/data.json/node-0-input-2.js").read_text(), "third()")

    def test_unexpected_errors_become_findings_not_crashes(self):
        # An error on one file must not prevent the remaining checks and the report
        self.put("a.json", json.dumps({"graph": {"nodes": []}}))
        self.put("b.json", json.dumps({"graph": {"nodes": [{"inputs": [{"alias": "code", "value": {"data": "x()"}}]}]}}))
        orig = inv.graphs_in
        inv.graphs_in = lambda doc: (_ for _ in ()).throw(RuntimeError("kaputt")) if doc["graph"]["nodes"] == [] else orig(doc)
        try:
            rc, rep = self.run_inventory()
        finally:
            inv.graphs_in = orig
        self.assertEqual(rc, 0)
        self.assertEqual(self.found(rep), {("a.json", "inventory-uninspected-json", "inspection-error")})
        self.assertEqual([w["source"] for w in rep["workflow_code"]], ["b.json"])

    def test_deeply_nested_manifest_does_not_crash(self):
        self.put("manifest.json", "[" * 100000 + "]" * 100000)
        rc, rep = self.run_inventory()
        self.assertEqual(rc, 0)
        self.assertEqual(self.found(rep), {("manifest.json", "inventory-uninspected-json", "too-deep")})

    def test_large_json_after_whitespace_is_reported(self):
        self.put("big.dat", " " * 1000 + "{" + "x" * 1000)
        self.put("big.js", "var x = 1;" + " " * 2000)
        orig = inv.MAX_WORKFLOW_JSON
        inv.MAX_WORKFLOW_JSON = 500
        try:
            _, rep = self.run_inventory()
        finally:
            inv.MAX_WORKFLOW_JSON = orig
        self.assertEqual(self.found(rep), {("big.dat", "inventory-uninspected-json", "too-large")})

    def test_workflow_json_that_cannot_be_inspected_is_reported(self):
        # Too large or nested too deeply: the code inside would stay unchecked
        big = json.dumps({"graph": {"nodes": [{"inputs": [{"alias": "code", "value": {"data": "eval(i)"}}]}]},
                          "pad": "x" * 400000})
        self.put("w/big.json", big)
        self.put("w/deep.json", "[" * 100000 + "]" * 100000)
        orig = inv.MAX_WORKFLOW_JSON
        inv.MAX_WORKFLOW_JSON = 300000  # big.json is above it, deep.json (200 KB) below
        try:
            _, rep = self.run_inventory()
        finally:
            inv.MAX_WORKFLOW_JSON = orig
        self.assertEqual(self.found(rep), {("w/big.json", "inventory-uninspected-json", "too-large"),
                                           ("w/deep.json", "inventory-uninspected-json", "too-deep")})
        self.assertEqual(rep["workflow_code"], [])

    def test_existing_derived_folder_fails(self):
        self.put("__workflow_code__/x.js", "harmlos()")
        rc, rep = self.run_inventory()
        self.assertEqual(rc, 1)
        self.assertIsNone(rep)


if __name__ == "__main__":
    unittest.main()
