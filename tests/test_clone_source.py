"""clone-source.sh fetches the source exactly at the release tag."""
import os, subprocess, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "clone-source.sh"
ENV = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
       "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
       "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
       # The tests clone local repos; otherwise the script allows only HTTPS
       "GIT_ALLOW_PROTOCOL": "file"}


def git(cwd, *args):
    return subprocess.run(["git", "-C", str(cwd), *args], env=ENV, check=True,
                          capture_output=True, text=True).stdout.strip()


def commit(repo, content):
    (repo / "pnpm-lock.yaml").write_text(content)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", content)
    return git(repo, "rev-parse", "HEAD")


class CloneSourceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.upstream = self.tmp / "upstream"
        self.upstream.mkdir()
        git(self.upstream, "init", "-q", "-b", "main")
        self.release = commit(self.upstream, "release")
        git(self.upstream, "tag", "-a", "1.0.0", "-m", "release")
        git(self.upstream, "checkout", "-q", "-b", "1.0.0")
        commit(self.upstream, "branch")
        git(self.upstream, "checkout", "-q", "main")
        self.head = commit(self.upstream, "head")
        self.url = self.upstream.resolve().as_uri()

    def tearDown(self):
        subprocess.run(["rm", "-rf", "--", str(self.tmp)], check=True)

    def clone(self, *tag):
        out = self.tmp / "src"
        out.mkdir()
        proc = subprocess.run(["bash", str(SCRIPT), self.url, str(out), *tag], env=ENV,
                              capture_output=True, text=True)
        return proc, out

    def test_tag_wins_over_branch_with_same_name(self):
        proc, out = self.clone("1.0.0")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(git(out, "rev-parse", "HEAD"), self.release)
        self.assertEqual((out / "pnpm-lock.yaml").read_text(), "release")

    def test_without_tag_clones_default_branch(self):
        proc, out = self.clone()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(git(out, "rev-parse", "HEAD"), self.head)

    def test_missing_tag_fails(self):
        proc, _ = self.clone("2.0.0")
        self.assertNotEqual(proc.returncode, 0)

    def test_invalid_tag_is_rejected(self):
        proc, _ = self.clone("1.0.0:refs/heads/x")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("invalid tag name", proc.stdout)

    def test_only_https_by_default(self):
        out = self.tmp / "src"
        out.mkdir()
        env = {k: v for k, v in ENV.items() if k != "GIT_ALLOW_PROTOCOL"}
        proc = subprocess.run(["bash", str(SCRIPT), self.url, str(out)], env=env, capture_output=True, text=True)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("transport 'file' not allowed", proc.stderr)

    def test_symlinks_become_files_and_lfs_pointers_stay(self):
        (self.upstream / "link").symlink_to("/etc/passwd")
        (self.upstream / ".gitattributes").write_text("*.bin filter=lfs diff=lfs merge=lfs -text\n")
        (self.upstream / "big.bin").write_text("version https://git-lfs.github.com/spec/v1\noid sha256:"
                                               + "0" * 64 + "\nsize 999999999\n")
        git(self.upstream, "add", "-A")
        git(self.upstream, "commit", "-q", "-m", "lfs")
        proc, out = self.clone()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertFalse((out / "link").is_symlink())
        self.assertEqual((out / "link").read_text(), "/etc/passwd")
        self.assertTrue((out / "big.bin").read_text().startswith("version https://git-lfs"))


if __name__ == "__main__":
    unittest.main()
