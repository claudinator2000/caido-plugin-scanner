"""Tests for scripts/semgrep_fallback.py (fallback scan on parser errors).

The unit tests simulate Semgrep and the splitter. The integration test uses real
Semgrep and the acorn splitter; it runs when SEMGREP_VERSION is set and
scripts/js-split/node_modules is installed. With REQUIRE_INTEGRATION=1 it fails
instead of being skipped (as in rules-test.yml).
"""
import importlib.util, json, os, shutil, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("semgrep_fallback", ROOT / "scripts" / "semgrep_fallback.py")
fb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fb)

SRC = 'const a = 1;\nclass as {\n  m() { return as; }\n}\nconst u = atob("aHR0cHM6Ly9jb2xsZWN0b3IuaW52YWxpZA==");\nfetch(u);\n'


def syntax_error(path):
    return {"type": "Syntax error", "level": "error", "path": path, "message": "Syntax error at line 1"}


class MaskTest(unittest.TestCase):
    def test_mask_keeps_length_lines_and_block(self):
        data = "é = 1;\nfoo();\nbar();\n".encode()
        start = data.index(b"foo")
        end = data.index(b"\nbar")
        out = fb.mask(data, start, end)
        self.assertEqual(len(out), len(data))
        self.assertEqual(out.count(b"\n"), data.count(b"\n"))
        self.assertEqual(out[start:end], b"foo();")
        self.assertEqual(out.replace(b"\n", b"").replace(b" ", b""), b"foo();")

    def test_neutralizes_comment_markers(self):
        # Semgrep's lexer takes <!-- and --> for HTML comments even in regex literals
        data = b"const r = [/^<!--/, /-->/];"
        a, b = data.index(b"<!--"), data.index(b"-->")
        out = fb.mask(data, 0, len(data), neutral=[(a, a + 4), (b, b + 3)])
        self.assertEqual(out, b"const r = [/^<!__/, /__>/];")

    def test_renames_only_inside_block(self):
        data = b"as; as;"
        out = fb.mask(data, 4, 7, renames=[(0, 2), (4, 6)])
        self.assertEqual(out[4:6], "ª".encode())
        self.assertEqual(out[:2], b"  ")


class FallbackLogicTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        self.js = self.d / "target" / "app.js"
        self.js.parent.mkdir()
        self.js.write_text(SRC)
        self.sg = self.d / "semgrep.json"

    def tearDown(self):
        self.tmp.cleanup()

    def write_sg(self, errors):
        self.sg.write_text(json.dumps({"results": [], "errors": errors, "paths": {"scanned": [str(self.js)]}}))

    def fake_splitter(self, path):
        data = Path(path).read_bytes()
        cut = data.index(b"const u")
        return {"blocks": [[0, cut - 1], [cut, len(data) - 1]], "renames": []}

    def runner(self, block_errors=(), whole_errors=()):
        """Simulates Semgrep. First call: the whole file as a copy (whole_errors), then
        the blocks (block_errors for the first block)."""
        calls = []

        def run(directory, out):
            copies = sorted(str(p) for p in Path(directory).rglob("app.js"))
            calls.append(len(copies))
            results = [{"check_id": "rules.obf-decode-into-call", "path": copies[-1],
                        "start": {"line": 6, "col": 1, "offset": 85}, "end": {"line": 6, "col": 9, "offset": 93},
                        "extra": {"severity": "WARNING"}}]
            errs = whole_errors if len(calls) == 1 else block_errors
            errors = [dict(e, path=copies[0]) for e in errs]
            return {"results": results, "errors": errors}
        run.calls = calls
        return run

    def test_whole_file_and_blocks_are_both_scanned(self):
        # Both stages always run; their matches are merged
        self.write_sg([syntax_error(str(self.js))])
        run = self.runner()
        fb.main(str(self.d / "target"), str(self.sg), runner=run, splitter=self.fake_splitter)
        sg = json.loads(self.sg.read_text())
        self.assertEqual(run.calls, [1, 2])
        self.assertEqual(sg["errors"], [])
        # The same match from both stages appears once
        self.assertEqual([r["path"] for r in sg["results"]], [str(self.js)])
        self.assertEqual(sg["fallback"], [{"path": str(self.js), "blocks": 2, "whole_file": True, "complete": True}])

    def test_either_stage_completes_the_file(self):
        for whole, block in (([syntax_error("x")], []), ([], [syntax_error("x")])):
            with self.subTest(whole=bool(whole), block=bool(block)):
                self.write_sg([syntax_error(str(self.js))])
                fb.main(str(self.d / "target"), str(self.sg), splitter=self.fake_splitter,
                        runner=self.runner(whole_errors=whole, block_errors=block))
                sg = json.loads(self.sg.read_text())
                self.assertEqual(sg["errors"], [])
                self.assertTrue(sg["fallback"][0]["complete"])

    def test_block_still_failing_keeps_error(self):
        self.write_sg([syntax_error(str(self.js))])
        fb.main(str(self.d / "target"), str(self.sg), splitter=self.fake_splitter,
                runner=self.runner(whole_errors=[syntax_error("x")], block_errors=[syntax_error("x")]))
        sg = json.loads(self.sg.read_text())
        types = [fb.error_type(e) for e in sg["errors"]]
        self.assertEqual(types, ["Syntax error", "Syntax error"])
        self.assertTrue(all(e["path"] == str(self.js) for e in sg["errors"]))
        self.assertFalse(sg["fallback"][0]["complete"])

    def test_timeouts_from_either_stage_are_kept(self):
        # Parsing alone is not enough: if a rule aborted, the file is not checked
        timeout = {"type": "Timeout", "path": "x", "message": "rule timed out", "rule_id": "rules.obf-decode-into-call"}
        for whole, block in (([timeout], []), ([], [timeout])):
            with self.subTest(whole=bool(whole), block=bool(block)):
                self.write_sg([syntax_error(str(self.js))])
                fb.main(str(self.d / "target"), str(self.sg), splitter=self.fake_splitter,
                        runner=self.runner(whole_errors=whole, block_errors=block))
                sg = json.loads(self.sg.read_text())
                self.assertEqual([(fb.error_type(e), e["path"]) for e in sg["errors"]], [("Timeout", str(self.js))])

    def test_partial_parsing_is_handled_like_syntax_errors(self):
        # With PartialParsing Semgrep skips parts of the file: it does not count as checked
        partial = [{"type": ["PartialParsing", []], "path": str(self.js), "message": "x"},
                   {"type": ["PartialParsing", []], "path": str(self.js), "message": "y"}]
        self.write_sg(partial)
        fb.main(str(self.d / "target"), str(self.sg), runner=self.runner(), splitter=self.fake_splitter)
        sg = json.loads(self.sg.read_text())
        self.assertEqual(sg["errors"], [])
        self.write_sg(partial)
        fb.main(str(self.d / "target"), str(self.sg), splitter=self.fake_splitter,
                runner=self.runner(whole_errors=[partial[0]], block_errors=[partial[0]]))
        sg = json.loads(self.sg.read_text())
        self.assertEqual([fb.error_type(e) for e in sg["errors"]], ["PartialParsing"] * 3)

    def test_unsplittable_file_keeps_error(self):
        self.write_sg([syntax_error(str(self.js))])
        fb.main(str(self.d / "target"), str(self.sg), runner=self.runner(), splitter=lambda p: None)
        sg = json.loads(self.sg.read_text())
        self.assertEqual([fb.error_type(e) for e in sg["errors"]], ["Syntax error"])

    def test_implausible_blocks_keep_error(self):
        # Splitter output that does not fit the file must not produce an empty scan reported as "complete"
        size = len(self.js.read_bytes())
        for bad in ({"blocks": [[size + 10, size + 40]], "renames": []},
                    {"blocks": [[0, 3], [3, 3]], "renames": []},
                    {"blocks": [[0, size - 1]], "renames": [[0, 2]]},
                    {"blocks": [[0, size - 1]], "renames": [], "neutral": [[0, 3]]}):
            with self.subTest(split=bad):
                self.write_sg([syntax_error(str(self.js))])
                called = []
                fb.main(str(self.d / "target"), str(self.sg), splitter=lambda p, b=bad: b,
                        runner=lambda *a: called.append(a) or {"results": [], "errors": []})
                sg = json.loads(self.sg.read_text())
                self.assertEqual([fb.error_type(e) for e in sg["errors"]], ["Syntax error"])
                self.assertEqual(called, [])

    def test_non_js_and_other_errors_untouched(self):
        ts = self.d / "target" / "app.ts"
        ts.write_text("let a: number = 1;\n")
        errors = [syntax_error(str(ts)), {"type": "Timeout", "path": str(self.js), "message": "x"}]
        self.write_sg(errors)
        called = []
        fb.main(str(self.d / "target"), str(self.sg), runner=lambda *a: called.append(a), splitter=self.fake_splitter)
        self.assertEqual(called, [])
        self.assertEqual(json.loads(self.sg.read_text())["errors"], errors)


def integration_available():
    return bool(os.environ.get("SEMGREP_VERSION")) and shutil.which("node") and shutil.which("uvx") \
        and (ROOT / "scripts" / "js-split" / "node_modules" / "acorn").is_dir()


class FallbackIntegrationTest(unittest.TestCase):
    def setUp(self):
        if not integration_available():
            if os.environ.get("REQUIRE_INTEGRATION"):
                self.fail("SEMGREP_VERSION, node, uvx or scripts/js-split/node_modules missing")
            self.skipTest("Semgrep/acorn not available")
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)

    def tearDown(self):
        if hasattr(self, "tmp"):
            self.tmp.cleanup()

    def test_splitter_renames_cover_only_as_identifiers(self):
        # Shorthand {as} yields the same identifier as key and value
        js = self.d / "a.js"
        js.write_text("class as {}; const o = {as}; as;\nconst é = 1; as;\n")
        split = fb.split_blocks(js)
        data = js.read_bytes()
        self.assertEqual([data[s:e] for s, e in split["renames"]], [b"as"] * 4)

    def test_splitter_finds_comment_markers_in_regex_and_strings(self):
        js = self.d / "m.js"
        js.write_text("const é = [/^<!--/, /-->/]; const s = '<!-- x -->'; // <!-- comment\nx = a-->b;\n")
        split = fb.split_blocks(js)
        data = js.read_bytes()
        found = [data[s:e] for s, e in split["neutral"]]
        self.assertEqual(found, [b"<!--", b"-->", b"<!--", b"-->"])  # not in the comment, not a-->b

    def test_splitter_handles_overlapping_markers(self):
        # "<!-->" contains both markers overlapping (e.g. empty HTML comments in Markdown parsers)
        js = self.d / "o.js"
        js.write_text("const r = /<!-->/; const s = '<!---->';\n")
        split = fb.split_blocks(js)
        self.assertIsNotNone(split)
        data = js.read_bytes()
        self.assertEqual([data[s:e] for s, e in split["neutral"]], [b"<!--", b"<!--", b"-->"])
        out = fb.mask(data, 0, len(data), neutral=split["neutral"])
        self.assertNotIn(b"<!--", out)
        self.assertNotIn(b"-->", out)

    def test_real_semgrep_partial_parsing_is_resolved(self):
        # Excerpt from a store bundle (HTML block rules of a Markdown parser): Semgrep's
        # parser skips parts of it when the file is large enough for it to fall back to
        # tree-sitter. Regardless, the fallback scan must resolve a PartialParsing error.
        js = self.d / "target" / "md.js"
        js.parent.mkdir()
        js.write_text("const Ad = [\n  [/^<!--/, /-->/, !0],\n  [/^<\\?/, /\\?>/, !0]\n];\n"
                      "const u = atob(\"aHR0cHM6Ly9ldmlsLmludmFsaWQ=\");\nfetch(u);\n")
        sg = self.d / "semgrep.json"
        sg.write_text(json.dumps({"results": [], "paths": {"scanned": [str(js)]},
                                  "errors": [{"type": ["PartialParsing", []], "path": str(js), "message": "x"}]}))
        fb.main(str(self.d / "target"), str(sg))
        out = json.loads(sg.read_text())
        self.assertEqual(out["errors"], [])
        self.assertTrue(out["fallback"][0]["complete"])
        self.assertTrue(any(r["check_id"].endswith("obf-decode-into-call") for r in out["results"]))

    def test_splitter_rejects_invalid_utf8(self):
        js = self.d / "bad.js"
        js.write_bytes(b"/* " + b"\x80" * 100 + b' */\nclass as {}; eval("payload");\n')
        self.assertIsNone(fb.split_blocks(js))

    def test_splitter_keeps_utf8_bom_in_offsets(self):
        js = self.d / "bom.js"
        js.write_bytes(b"\xef\xbb\xbfclass as {};\neval(\"x\");\n")
        split = fb.split_blocks(js)
        data = js.read_bytes()
        self.assertEqual([data[s:e] for s, e in split["renames"]], [b"as"])
        self.assertTrue(data[slice(*split["blocks"][-1])].endswith(b'eval("x");'))

    def test_real_semgrep_and_splitter_map_findings_to_original(self):
        js = self.d / "target" / "app.js"
        js.parent.mkdir()
        # Multi-byte characters before the match check the byte offsets
        js.write_text("const é = 'ü';\n" + SRC)
        sg = self.d / "semgrep.json"
        sg.write_text(json.dumps({"results": [], "errors": [syntax_error(str(js))],
                                  "paths": {"scanned": [str(js)]}}))
        fb.main(str(self.d / "target"), str(sg))
        out = json.loads(sg.read_text())
        self.assertEqual(out["errors"], [])
        self.assertTrue(out["fallback"][0]["complete"])
        hits = [r for r in out["results"] if r["check_id"].endswith("obf-decode-into-call")]
        self.assertEqual(len(hits), 1)
        hit = hits[0]
        self.assertEqual(hit["path"], str(js))
        self.assertEqual(hit["start"]["line"], 7)
        data = js.read_bytes()
        self.assertEqual(data[hit["start"]["offset"]:hit["end"]["offset"]], b"fetch(u)")


if __name__ == "__main__":
    unittest.main()
