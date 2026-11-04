"""Tests for scripts/watch.py (selection of plugins to scan, stored state)."""
import datetime, hashlib, importlib.util, json, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("watch", ROOT / "scripts" / "watch.py")
watch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(watch)

SHA = "5f70f93912f7bb94994436828bce7a6d78757d82"
TAG_SHA = "a" * 40
DIGEST = "sha256:" + "ab" * 32
CONFIG = "c" * 64


def release(*assets):
    return {"tag_name": "1.0.0", "assets": list(assets)}


def asset(name="plugin_package.zip", id=11, updated="2026-01-23T22:15:42Z", digest=DIGEST):
    return {"name": name, "id": id, "updated_at": updated, "digest": digest}


def plugin(pid, repo=None):
    return {"id": pid, "repo": repo or f"owner/{pid}", "store": True}


def key(asset_id=11, config=CONFIG, baseline="b", head=SHA):
    return (f"repo=owner/p;asset={asset_id};updated=2026-01-23T22:15:42Z;digest=-;head={head};"
            f"config={config};baseline={baseline}")


class KeyTest(unittest.TestCase):
    def key(self, rel, head=SHA, repo="owner/p", tag_commit=TAG_SHA):
        commits = {"HEAD": head, "refs/tags/1.0.0": tag_commit}
        return watch.key_for(repo, lambda r: rel, lambda r, ref: commits.get(ref))

    def test_release_asset_and_tag_commit_identify_plugin(self):
        # The release tag's commit is part of it: that is where the lockfile OSV checks lives
        self.assertEqual(self.key(release(asset())),
                         f"repo=owner/p;asset=11;updated=2026-01-23T22:15:42Z;digest={DIGEST};"
                         f"tag=1.0.0;commit={TAG_SHA}")

    def test_release_asset_without_digest(self):
        self.assertIn(";digest=-;tag=1.0.0;", self.key(release(asset(digest=None))))

    def test_without_release_or_asset_uses_head(self):
        self.assertEqual(self.key(None), f"repo=owner/p;head={SHA}")
        self.assertEqual(self.key(release(asset(name="other.zip"))), f"repo=owner/p;head={SHA}")

    def test_lookup_errors_and_odd_values_give_no_key(self):
        def fail(_):
            raise watch.LookupFailed("503")
        self.assertIsNone(watch.key_for("owner/p", fail, lambda r, ref: SHA))
        self.assertIsNone(self.key(None, head=None))
        self.assertIsNone(self.key(None, head="HEAD;config=x"))
        self.assertIsNone(self.key(release(asset()), tag_commit=None))
        for tag in ("../x", "a b", "1.0;x", "", None, 3):
            with self.subTest(tag=tag):
                rel = dict(release(asset()), tag_name=tag)
                self.assertIsNone(watch.key_for("owner/p", lambda r: rel, lambda r, ref: TAG_SHA))
        for bad in (asset(id="11;head=x"), asset(updated="x;config=y"), asset(digest="md5:abc"),
                    asset(id=True)):
            with self.subTest(asset=bad):
                self.assertIsNone(self.key(release(bad)))

    def test_full_key_adds_config_and_baseline(self):
        self.assertEqual(watch.full_key("repo=a/b;head=x", CONFIG, "-", ""),
                         f"repo=a/b;head=x;config={CONFIG};baseline=-;key=-")
        self.assertIsNone(watch.full_key(None, CONFIG, "-", ""))

    def test_store_key_change_triggers_scan(self):
        # A changed or removed store key must trigger a new signature check
        a = watch.full_key("repo=a/b;head=x", CONFIG, "-", "MCowBQYDK2VwAyEAaaaa")
        b = watch.full_key("repo=a/b;head=x", CONFIG, "-", "MCowBQYDK2VwAyEAbbbb")
        none = watch.full_key("repo=a/b;head=x", CONFIG, "-", "")
        self.assertEqual(watch.reason(a, b), "store key changed")
        self.assertEqual(watch.reason(a, none), "store key changed")
        self.assertNotIn("MCow", a)


class SelectTest(unittest.TestCase):
    def test_selects_by_reason(self):
        plugins = [plugin(n) for n in ("same", "new", "release", "config", "baseline", "unknown")]
        plugins.append(plugin("head"))
        state = {"same": key(), "release": key(), "config": key(), "baseline": key(), "unknown": key(),
                 "head": key()}
        keys = {"same": key(), "new": key(), "release": key(asset_id=12), "config": key(config="d" * 64),
                "baseline": key(baseline="x"), "unknown": None, "head": key(head="a" * 40)}
        chosen = watch.select(plugins, keys, state)
        self.assertEqual([(p["id"], why) for p, why in chosen], [
            ("new", "new"), ("release", "release/repository state changed"),
            ("config", "scanner configuration changed"), ("baseline", "baseline changed"),
            ("unknown", "state not determinable"), ("head", "release/repository state changed")])

    def test_missing_state_selects_all_and_full_selects_unchanged(self):
        plugins = [plugin("a"), plugin("b")]
        self.assertEqual([p["id"] for p, _ in watch.select(plugins, {"a": key(), "b": key()}, {})], ["a", "b"])
        chosen = watch.select(plugins, {"a": key(), "b": key()}, {"a": key(), "b": key()}, full=True)
        self.assertEqual([why for _, why in chosen], ["full run"] * 2)


class BaselineStateTest(unittest.TestCase):
    def test_expiring_entry_changes_baseline_state(self):
        # findings.py no longer accepts expired entries: even without a file change, the
        # expiry must trigger a scan
        with tempfile.TemporaryDirectory() as d:
            b = Path(d) / "p.json"
            b.write_text(json.dumps({"accepted": [
                {"fingerprint": "f", "reason": "r", "owner": "o", "review_by": "2026-11-05"},
                {"fingerprint": "g", "reason": "r", "owner": "o", "review_by": "no date"}]}))
            before = watch.baseline_state(b, datetime.date(2026, 11, 5))
            after = watch.baseline_state(b, datetime.date(2026, 11, 6))
            self.assertNotEqual(before, after)
            self.assertEqual(before.split(":")[0], after.split(":")[0])
            self.assertEqual(watch.baseline_state(Path(d) / "missing.json", datetime.date(2026, 11, 6)), "-")
            b.write_text("kaputt")
            self.assertTrue(watch.baseline_state(b, datetime.date(2026, 11, 6)).endswith(":0"))
            self.assertEqual(watch.reason(key(baseline=before), key(baseline=after)), "baseline exception expired")


class CommandTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        (self.d / "baselines").mkdir()
        (self.d / "baselines" / "a.json").write_text('{"accepted": []}')

    def tearDown(self):
        self.tmp.cleanup()

    def run_select(self, mode, plugins, lookup):
        (self.d / "plugins.json").write_text(json.dumps(plugins))
        orig = watch.key_for
        watch.key_for = lambda repo: lookup(repo)
        try:
            watch.cmd_select(mode, self.d / "plugins.json", self.d / "state.json", CONFIG, self.d / "baselines",
                             self.d / "matrix.json", self.d / "keys.json", self.d / "summary.md")
        finally:
            watch.key_for = orig
        return json.loads((self.d / "matrix.json").read_text()), json.loads((self.d / "keys.json").read_text())

    def test_select_then_update_then_nothing_changed(self):
        plugins = [plugin("a"), plugin("b")]
        matrix, keys = self.run_select("changed", plugins, lambda r: f"repo={r};head={SHA}")
        self.assertEqual([p["id"] for p in matrix], ["a", "b"])
        self.assertIn(";baseline=" + hashlib.sha256((self.d / "baselines" / "a.json").read_bytes()).hexdigest() + ":0;",
                      keys["a"])
        self.assertIn(";baseline=-;", keys["b"])
        reports = self.d / "reports"
        for pid in ("a", "b"):
            (reports / f"report-{pid}").mkdir(parents=True)
            (reports / f"report-{pid}" / "report.json").write_text("{}")
            (reports / f"report-{pid}" / "source.txt").write_text(f"ref HEAD\ncommit {SHA}\n")
        (self.d / "matrix.json").write_text(json.dumps(plugins))
        watch.cmd_update(self.d / "state.json", self.d / "keys.json", self.d / "matrix.json", reports,
                         self.d / "state.json", self.d / "cache")
        matrix, _ = self.run_select("changed", plugins, lambda r: f"repo={r};head={SHA}")
        self.assertEqual(matrix, [])
        self.assertIn("No changes", (self.d / "summary.md").read_text())
        # With a selection: text visible, only the table collapsed
        md = watch.summary_md([(plugins[0], "new")], 2)
        self.assertLess(md.index("1 of 2 plugins"), md.index("<details>"))
        self.assertLess(md.index("<details>"), md.index("| Plugin | Reason |"))
        self.assertTrue(md.rstrip().endswith("</details>"))
        # A baseline change affects only this plugin
        (self.d / "baselines" / "a.json").write_text('{"accepted": [1]}')
        matrix, _ = self.run_select("changed", plugins, lambda r: f"repo={r};head={SHA}")
        self.assertEqual([p["id"] for p in matrix], ["a"])
        # A different store key likewise affects only its plugin
        (self.d / "baselines" / "a.json").write_text('{"accepted": []}')
        plugins[1]["public_key"] = "MCowBQYDK2VwAyEAneu"
        matrix, _ = self.run_select("changed", plugins, lambda r: f"repo={r};head={SHA}")
        self.assertEqual([p["id"] for p in matrix], ["b"])

    def test_many_unknown_aborts_instead_of_scanning_all(self):
        plugins = [plugin(f"p{i}") for i in range(watch.MAX_UNKNOWN + 1)]
        with self.assertRaises(SystemExit):
            self.run_select("changed", plugins, lambda r: None)
        matrix, _ = self.run_select("full", plugins, lambda r: None)
        self.assertEqual(len(matrix), len(plugins))

    def test_rejects_unsafe_plugin_list_and_config_hash(self):
        with self.assertRaises(SystemExit):
            self.run_select("changed", [plugin("a", repo="x/y;z")], lambda r: None)
        (self.d / "plugins.json").write_text("[]")
        with self.assertRaises(SystemExit):
            watch.cmd_select("changed", self.d / "plugins.json", self.d / "s", "x;y", self.d, self.d / "m",
                             self.d / "k", self.d / "s.md")


class UpdateTest(unittest.TestCase):
    def test_only_plugins_with_report_are_recorded(self):
        with tempfile.TemporaryDirectory() as d:
            reports = Path(d)
            for pid, name in (("done", "report.json"), ("incomplete", "semgrep.json"), ("nokey", "report.json"),
                              ("pushed", "report.json")):
                (reports / f"report-{pid}").mkdir()
                (reports / f"report-{pid}" / name).write_text("{}")
                # In the "pushed" case a new commit arrived between selection and scan
                commit = TAG_SHA if pid == "pushed" else SHA
                (reports / f"report-{pid}" / "source.txt").write_text(f"ref HEAD\ncommit {commit}\n")
            new = f"repo=owner/p;head={SHA};config={CONFIG};baseline=-"
            old = {"done": "old", "incomplete": "old", "untouched": "u", "failed": "f", "pushed": "old"}
            keys = {"done": new, "incomplete": new, "nokey": None, "missing": new, "../x": new,
                    "untouched": "u", "failed": "f", "pushed": new}
            selected = {"done", "incomplete", "nokey", "failed", "../x", "pushed"}
            # Selected without a report: the old state lapses, the next run repeats the scan
            self.assertEqual(watch.update(old, keys, reports, selected), {"done": new, "untouched": "u"})

    def test_release_key_needs_matching_scanned_zip(self):
        # If the ZIP download fails, the job scans the source: then the release key
        # must not count as scanned
        with tempfile.TemporaryDirectory() as d:
            reports = Path(d)
            digest = "ab" * 32
            with_digest = (f"repo=owner/p;asset=11;updated=2026-01-23T22:15:42Z;digest=sha256:{digest};"
                           f"tag=1.0.0;commit={TAG_SHA};config={CONFIG};baseline=-")
            without_digest = with_digest.replace(f"sha256:{digest}", "-")
            tag_src = f"ref 1.0.0\ncommit {TAG_SHA}\n"
            cases = {"match": (with_digest, f"{digest}  pkg.zip\n", tag_src),
                     "mismatch": (with_digest, f"{'cd' * 32}  pkg.zip\n", tag_src),
                     "source": (with_digest, None, tag_src),
                     "nodigest": (without_digest, f"{'cd' * 32}  pkg.zip\n", tag_src),
                     "nodigest-source": (without_digest, None, tag_src),
                     # ZIP matches, but the source (lockfile) was scanned from a different commit
                     "other-commit": (with_digest, f"{digest}  pkg.zip\n", f"ref 1.0.0\ncommit {SHA}\n"),
                     "no-source-file": (with_digest, f"{digest}  pkg.zip\n", None)}
            for pid, (_, sha, src) in cases.items():
                (reports / f"report-{pid}").mkdir()
                (reports / f"report-{pid}" / "report.json").write_text("{}")
                if sha is not None:
                    (reports / f"report-{pid}" / "sha256.txt").write_text(sha)
                if src is not None:
                    (reports / f"report-{pid}" / "source.txt").write_text(src)
            keys = {pid: k for pid, (k, *_) in cases.items()}
            old = {pid: "old" for pid in cases}
            self.assertEqual(watch.update(old, keys, reports, set(cases)),
                             {"match": with_digest, "nodigest": without_digest})


class LoadStateTest(unittest.TestCase):
    def test_missing_or_broken_state_is_empty(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "state.json"
            self.assertEqual(watch.load_state(p), {})
            for content in ("not json", "[]", json.dumps({"version": 2, "plugins": {"a": "k"}})):
                p.write_text(content)
                self.assertEqual(watch.load_state(p), {})
            watch.save_state(p, {"a": "k"})
            data = json.loads(p.read_text()); data["plugins"]["b"] = 3; p.write_text(json.dumps(data))
            self.assertEqual(watch.load_state(p), {"a": "k"})


class ReportedTest(unittest.TestCase):
    """One alarm per finding and plugin state."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def key(self, head=SHA, config=CONFIG):
        return watch.full_key(f"repo=o/a;head={head}", config, "-", "")

    def report(self, pid, blocking, commit=SHA):
        d = self.d / "reports" / f"report-{pid}"
        d.mkdir(parents=True, exist_ok=True)
        (d / "source.txt").write_text(f"ref HEAD\ncommit {commit}\n")
        (d / "report.json").write_text(json.dumps({"plugin": pid, "version": {"commit": commit},
                                                   "new_blocking": {f: {"rule": "r"} for f in blocking},
                                                   "new_info": {"1111111111111111": {"rule": "i", "where": "w",
                                                                                     "context": {"x": "y"}}},
                                                   "accepted": {}, "known_blocking": [], "baseline_problems": [],
                                                   "all": {"big": 1}}))

    def test_known_only_for_same_plugin_state(self):
        self.report("a", ["aaaaaaaaaaaaaaaa"])
        reported = watch.update_reported({}, {"a": self.key()}, self.d / "reports", {"a"})
        self.assertEqual(watch.known_for(reported, "a", self.key()), ["aaaaaaaaaaaaaaaa"])
        # New scanner configuration: same plugin state, findings stay reported
        self.assertEqual(watch.known_for(reported, "a", self.key(config="c" * 64)), ["aaaaaaaaaaaaaaaa"])
        # Plugin update: everything alarms again
        self.assertEqual(watch.known_for(reported, "a", self.key(head="b" * 40)), [])
        self.assertEqual(watch.known_for(reported, "b", self.key()), [])

    def test_finding_absent_for_a_while_stays_reported(self):
        self.report("a", ["aaaaaaaaaaaaaaaa"])
        reported = watch.update_reported({}, {"a": self.key()}, self.d / "reports", {"a"})
        # Accepted in the baseline: the scan no longer reports it
        self.report("a", [])
        reported = watch.update_reported(reported, {"a": self.key()}, self.d / "reports", {"a"})
        self.assertEqual(watch.known_for(reported, "a", self.key()), ["aaaaaaaaaaaaaaaa"])
        # New plugin state: nothing counts as reported any more
        self.report("a", ["bbbbbbbbbbbbbbbb"], commit="b" * 40)
        reported = watch.update_reported(reported, {"a": self.key(head="b" * 40)}, self.d / "reports", {"a"})
        self.assertEqual(watch.known_for(reported, "a", self.key(head="b" * 40)), ["bbbbbbbbbbbbbbbb"])

    def test_unverified_scan_records_nothing(self):
        reported = watch.update_reported({}, {"a": self.key()}, self.d / "reports", {"a"})
        self.assertEqual(reported, {})
        release = "repo=o/a;asset=1;updated=2026-01-01T00:00:00Z;digest=-;tag=v1;commit=" + SHA
        self.report("b", ["aaaaaaaaaaaaaaaa"])  # without sha256.txt/source.txt
        reported = watch.update_reported({}, {"b": watch.full_key(release, CONFIG, "-", "")}, self.d / "reports", {"b"})
        self.assertEqual(reported, {})

    def test_push_between_selection_and_scan_records_nothing(self):
        # HEAD A was selected, B was cloned: B's findings do not belong to A
        self.report("a", ["aaaaaaaaaaaaaaaa"], commit="b" * 40)
        self.assertEqual(watch.update_reported({}, {"a": self.key()}, self.d / "reports", {"a"}), {})
        watch.cache_reports({"a": self.key()}, self.d / "reports", {"a"}, self.d / "cache", "2026-11-03", "")
        self.assertFalse((self.d / "cache" / "a.json").exists())

    def test_state_file_round_trip_and_invalid_entries(self):
        p = self.d / "state.json"
        watch.save_state(p, {"a": "k"}, {"a": {"plugin": "repo=o/a", "fps": ["aaaaaaaaaaaaaaaa"]},
                                         "b": {"plugin": "x", "fps": ["not-a-fingerprint"]},
                                         "../c": {"plugin": "x", "fps": []}})
        self.assertEqual(watch.load_state(p), {"a": "k"})
        self.assertEqual(watch.load_reported(p), {"a": {"plugin": "repo=o/a", "fps": ["aaaaaaaaaaaaaaaa"]}})
        p.write_text('{"version": 1, "plugins": {"a": "k"}}')  # state without "reported" (before this change)
        self.assertEqual(watch.load_reported(p), {})

    def test_matrix_carries_known_findings(self):
        (self.d / "baselines").mkdir()
        plugins = [{"id": "a", "repo": "o/a", "store": False, "public_key": ""}]
        (self.d / "plugins.json").write_text(json.dumps(plugins))
        state = self.d / "state.json"
        k = watch.full_key(f"repo=o/a;head={SHA}", CONFIG, "-", "")
        watch.save_state(state, {}, {"a": {"plugin": watch.plugin_state(k), "fps": ["aaaaaaaaaaaaaaaa"]}})
        orig = watch.key_for
        watch.key_for = lambda repo: f"repo={repo};head={SHA}"
        try:
            watch.cmd_select("full", self.d / "plugins.json", state, CONFIG, self.d / "baselines",
                             self.d / "m.json", self.d / "k.json", self.d / "s.md")
        finally:
            watch.key_for = orig
        entry = json.loads((self.d / "m.json").read_text())[0]
        self.assertEqual(entry["known"], ["aaaaaaaaaaaaaaaa"])
        self.assertEqual(entry["known_state"], f"repo=o/a;head={SHA}")

    def test_cache_keeps_small_copy_of_verified_reports(self):
        self.report("a", ["aaaaaaaaaaaaaaaa"])
        cache = self.d / "cache"
        watch.cache_reports({"a": self.key(), "b": self.key()}, self.d / "reports", {"a", "b"}, cache,
                            "2026-11-03", "https://github.com/o/r/actions/runs/1")
        self.assertEqual(sorted(f.name for f in cache.iterdir()), ["a.json"])
        small = json.loads((cache / "a.json").read_text())
        self.assertEqual(list(small["new_blocking"]), ["aaaaaaaaaaaaaaaa"])
        self.assertNotIn("all", small)
        self.assertEqual(small["version"], {"commit": SHA})
        self.assertEqual(small["new_info"], {"1111111111111111": {"rule": "i", "where": "w"}})
        self.assertEqual((small["scanned_at"], small["run_url"]), ("2026-11-03", "https://github.com/o/r/actions/runs/1"))


if __name__ == "__main__":
    unittest.main()
