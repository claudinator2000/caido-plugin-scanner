"""adhoc-plugin.sh: plugin list for a single scan from the free-form input "repo"."""
import json, subprocess, tempfile, unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "adhoc-plugin.sh"


class AdhocTest(unittest.TestCase):
    def run_script(self, repo):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "all.json"
            proc = subprocess.run(["bash", str(SCRIPT), repo, str(out)], capture_output=True, text=True)
            return proc, (json.loads(out.read_text()) if out.exists() else None)

    def test_valid_repo(self):
        proc, plugins = self.run_script("karanshergill/graphx")
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertEqual(plugins, [{"id": "adhoc-graphx", "repo": "karanshergill/graphx", "store": False,
                                    "public_key": ""}])

    def test_accepted_forms(self):
        for given in ("53cur3M3/caido-jwt-attacker", "  53cur3M3/caido-jwt-attacker  ",
                      "jwt-attacker 53cur3M3/caido-jwt-attacker",
                      "https://github.com/53cur3M3/caido-jwt-attacker",
                      "https://github.com/53cur3M3/caido-jwt-attacker/",
                      "https://github.com/53cur3M3/caido-jwt-attacker.git"):
            proc, plugins = self.run_script(given)
            self.assertEqual(proc.returncode, 0, given)
            self.assertEqual(plugins[0]["repo"], "53cur3M3/caido-jwt-attacker", given)
            self.assertEqual(plugins[0]["id"], "adhoc-caido-jwt-attacker", given)

    def test_error_names_the_expected_form(self):
        proc, _ = self.run_script("jwt-attacker")
        self.assertIn("maintainer/repo, e.g.", proc.stdout)

    def test_unsafe_input_is_rejected(self):
        for repo in ("", "graphx", "a/b/c", "a/b;id", "../x", "a/..", "a/.", "a/b\nc", "a/b\nc/d",
                     "-/x" + "y" * 200, "$(id)/x", "a/`id`", "http://github.com/a/b",
                     "https://evil.example/a/b", "https://github.com/a/b/tree/main", "a/b.git.git/x"):
            proc, plugins = self.run_script(repo)
            self.assertNotEqual(proc.returncode, 0, repo)
            self.assertIsNone(plugins, repo)


if __name__ == "__main__":
    unittest.main()
