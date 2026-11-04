"""Output containing untrusted data must not trigger GitHub workflow commands.

GitHub evaluates every log line that starts with "::". File names from plugins
can contain line breaks and thereby create such lines.
"""
import contextlib, importlib.util, io, json, subprocess, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "scripts" / "no-workflow-commands.sh"
spec = importlib.util.spec_from_file_location("semgrep_fallback", ROOT / "scripts" / "semgrep_fallback.py")
fb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fb)


class WrapperTest(unittest.TestCase):
    def run_wrapped(self, script):
        return subprocess.run(["bash", str(WRAPPER), "bash", "-c", script], capture_output=True, text=True)

    def test_output_is_enclosed_by_stop_and_resume(self):
        proc = self.run_wrapped("printf 'a\\n::add-mask::secret\\nb\\n'")
        lines = proc.stdout.splitlines()
        self.assertTrue(lines[0].startswith("::stop-commands::"))
        token = lines[0].split("::stop-commands::", 1)[1]
        self.assertRegex(token, r"^[0-9a-f]{32}$")
        self.assertEqual(lines[-1], f"::{token}::")
        self.assertEqual(lines[1:-1], ["a", "::add-mask::secret", "b"])

    def test_stderr_is_enclosed_too(self):
        proc = self.run_wrapped("echo '::warning::x' >&2")
        self.assertIn("::warning::x", proc.stdout)
        self.assertEqual(proc.stderr, "")

    def test_exit_code_is_kept(self):
        self.assertEqual(self.run_wrapped("exit 3").returncode, 3)
        self.assertEqual(self.run_wrapped("true").returncode, 0)

    def test_token_differs_per_run(self):
        first = self.run_wrapped("true").stdout.splitlines()[0]
        second = self.run_wrapped("true").stdout.splitlines()[0]
        self.assertNotEqual(first, second)


class FallbackDiagnosticsTest(unittest.TestCase):
    def test_paths_with_newlines_are_escaped(self):
        with tempfile.TemporaryDirectory() as d:
            js = Path(d) / "target" / "\n::add-mask::fetch\napp.js"
            js.parent.mkdir()
            js.write_text("a();\nb();\n")
            sg = Path(d) / "semgrep.json"
            sg.write_text(json.dumps({"results": [], "paths": {"scanned": [str(js)]},
                                      "errors": [{"type": "Syntax error", "path": str(js), "message": "x"}]}))
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                fb.main(str(js.parent), str(sg), runner=lambda *a: {"results": [], "errors": []},
                        splitter=lambda p: None)
                fb.main(str(js.parent), str(sg), runner=lambda *a: {"results": [], "errors": []},
                        splitter=lambda p: {"blocks": [[0, 4]], "renames": []})
            printed = out.getvalue()
            self.assertIn("Fallback scan", printed)
            self.assertFalse(any(line.startswith("::") for line in printed.splitlines()), printed)


if __name__ == "__main__":
    unittest.main()
