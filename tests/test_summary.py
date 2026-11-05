"""Tests for scripts/summary.py (overview of a scan run)."""
import importlib.util, json, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("summary", ROOT / "scripts" / "summary.py")
summary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(summary)


def finding(rule, where="backend/index.js:3", code="fetch(u)", tool="semgrep", severity="WARNING"):
    return {"tool": tool, "rule": rule, "severity": severity, "where": where, "code": code}


class SummaryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        self.reports = self.d / "reports"
        self.reports.mkdir()
        self.candidates = self.d / "candidates"
        self.plugins = []

    def tearDown(self):
        self.tmp.cleanup()

    def add(self, pid, blocking=(), info=(), problems=(), report=True):
        self.plugins.append({"id": pid, "repo": f"owner/{pid}", "store": True})
        if not report:
            return
        d = self.reports / f"report-{pid}"
        d.mkdir()
        rep = {"plugin": pid,
               "new_blocking": {f"b{i}": f for i, f in enumerate(blocking)},
               "new_info": {f"i{i}": f for i, f in enumerate(info)},
               "baseline_problems": list(problems), "baseline_stale": [],
               "all": {}, "baseline_candidate": {"accepted": [{"fingerprint": "abc", "reason": ""}]}}
        (d / "report.json").write_text(json.dumps(rep))

    def run_summary(self, limit=None, selected=None, cache=None):
        (self.d / "plugins.json").write_text(json.dumps(self.plugins))
        out = self.d / "summary.md"
        kwargs = {"limit": limit} if limit else {}
        if selected is not None:
            (self.d / "selected.json").write_text(json.dumps([{"id": s} for s in selected]))
            kwargs.update(selected_file=str(self.d / "selected.json"), cache_dir=str(cache or self.d / "cache"))
        summary.main(str(self.reports), str(self.d / "plugins.json"), str(out), str(self.candidates), **kwargs)
        return out.read_text()

    def cache(self, pid, blocking=(), known=(), scanned_at="2026-11-02",
              run_url="https://github.com/o/r/actions/runs/7"):
        c = self.d / "cache"
        c.mkdir(exist_ok=True)
        (c / f"{pid}.json").write_text(json.dumps({
            "plugin": pid, "new_blocking": {f"b{i}": f for i, f in enumerate(blocking)},
            "known_blocking": list(known), "accepted": {}, "baseline_problems": [], "new_info": {},
            "scanned_at": scanned_at, "run_url": run_url}))

    def row(self, md, pid):
        # First line of the table row: status, scan date, counts and head of the findings
        return next(l for l in md.splitlines() if l.startswith(f'<tr><td><a href="https://github.com/owner/{pid}">'))

    # Full overview and one alarm per finding

    def test_unscanned_plugins_shown_with_last_result(self):
        self.add("fresh")
        self.plugins.append({"id": "old", "repo": "owner/old", "store": True})
        self.cache("old", blocking=[finding("x")], known=["b0"])
        self.plugins.append({"id": "never", "repo": "owner/never", "store": True})
        md = self.run_summary(selected=["fresh"])
        self.assertIn("3 plugins** (1 scanned in this run", md)
        self.assertIn('🔴 open</td><td><a href="https://github.com/o/r/actions/runs/7">2026-11-02</a>',
                      self.row(md, "old"))
        self.assertIn("⚪ no result yet", self.row(md, "never"))
        self.assertIn("0 of them with a new finding", md)
        self.assertFalse((self.candidates / "old.json").exists())

    def test_scanned_plugin_without_report_never_uses_cache(self):
        self.add("broken", report=False)
        self.cache("broken", blocking=[], scanned_at="2026-11-01")
        md = self.run_summary(selected=["broken"])
        self.assertIn("⚪ no report</td><td>this run", self.row(md, "broken"))

    def test_one_red_status_with_new_findings_marked(self):
        self.add("p", blocking=[finding("x"), finding("y")])
        rep_file = self.reports / "report-p" / "report.json"
        rep = json.loads(rep_file.read_text())
        rep["known_blocking"] = ["b0", "b1"]
        rep_file.write_text(json.dumps(rep))
        row = self.row(self.run_summary(selected=["p"]), "p")
        self.assertIn("🔴 open", row)
        self.assertNotIn("new in this run", row)
        rep["known_blocking"] = ["b0"]
        rep_file.write_text(json.dumps(rep))
        row = self.row(self.run_summary(selected=["p"]), "p")
        self.assertIn("🔴 open", row)
        self.assertIn("<b>2 blocking</b> (1 new in this run)", row)

    def test_cached_report_never_marks_findings_new(self):
        self.plugins.append({"id": "old", "repo": "owner/old", "store": True})
        self.cache("old", blocking=[finding("x")], known=[])
        row = self.row(self.run_summary(selected=[]), "old")
        self.assertIn("🔴 open", row)
        self.assertNotIn("new in this run", row)

    def test_cached_run_url_must_be_an_actions_run(self):
        self.plugins.append({"id": "old", "repo": "owner/old", "store": True})
        self.cache("old", run_url="javascript:alert(1)", scanned_at="<b>")
        md = self.run_summary(selected=[])
        self.assertNotIn("javascript:", md)
        self.assertIn("<td>earlier</td>", self.row(md, "old"))

    def test_counts_and_status(self):
        self.add("clean")
        self.add("bad", blocking=[finding("obf-dynamic-code-exec"), finding("obf-dynamic-code-exec")])
        self.add("broken", report=False)
        md = self.run_summary()
        self.assertIn("3 plugins", md)
        self.assertIn("1 ok", md)
        self.assertIn("1 blocked, 1 of them with a new finding in this run", md)
        self.assertIn("1 without a report", md)
        self.assertIn("obf-dynamic-code-exec ×2", md)

    def test_sorted_problem_first(self):
        self.add("aaa-clean")
        self.add("zzz-bad", blocking=[finding("x")])
        self.add("mmm-broken", report=False)
        md = self.run_summary()
        table = md[md.index("<table>"):]
        self.assertLess(table.index("mmm-broken"), table.index("zzz-bad"))
        self.assertLess(table.index("zzz-bad"), table.index("aaa-clean"))

    def test_untrusted_text_is_escaped(self):
        evil = '<img src=x onerror=alert(1)> | `code` [link](https://evil.invalid)\n## heading'
        self.add("p", blocking=[finding("r", where=evil, code=evil)])
        md = self.run_summary()
        self.assertNotIn("<img", md)
        self.assertNotIn("](https://evil.invalid)", md)
        self.assertNotIn("\n## heading", md)
        self.assertIn("&lt;img", md)

    def test_escaping_is_single_pass(self):
        # Every character replaced exactly once: no entities inside entities
        self.assertEqual(summary.esc("a_b#c'd"), "a&#95;b&#35;c&#39;d")
        self.assertEqual(summary.esc("x<y>&z"), "x&lt;y&gt;&amp;z")
        self.assertNotIn("&&", summary.esc("_#`|[]*'\"<>&"))

    def test_baseline_candidates_written(self):
        self.add("p", blocking=[finding("r")])
        self.add("q", report=False)
        self.run_summary()
        self.assertEqual(json.loads((self.candidates / "p.json").read_text())["accepted"][0]["fingerprint"], "abc")
        self.assertFalse((self.candidates / "q.json").exists())

    def test_invalid_plugin_id_is_rejected(self):
        self.add("../escape", report=False)
        with self.assertRaises(ValueError):
            self.run_summary()

    def test_output_stays_under_limit(self):
        many = [finding(f"rule-{i}", code="x" * 250) for i in range(60)]
        for n in range(30):
            self.add(f"plugin-{n:02}", blocking=many)
        md = self.run_summary(limit=40_000)
        self.assertLessEqual(len(md.encode()), 40_000)
        self.assertIn("shortened", md)
        # The table names every plugin, even when the details are shortened
        self.assertTrue(all(f'owner/plugin-{n:02}">plugin-{n:02}</a>' in md for n in range(30)))

    def test_rule_column_is_capped(self):
        self.add("p", blocking=[finding(f"rule-{i}") for i in range(20)])
        md = self.run_summary()
        row = self.row(md, "p")
        self.assertIn("rule-0", row)
        self.assertNotIn("rule-19", row)
        self.assertIn("12 more", row)

    def test_version_column(self):
        self.add("rel"); self.add("src"); self.add("bad")
        for pid, v in (("rel", {"tag": "v1.2.0", "commit": "a" * 40}), ("src", {"commit": "b" * 40}),
                       ("bad", {"tag": '"><script>', "commit": "x"})):
            f = self.reports / f"report-{pid}" / "report.json"
            rep = json.loads(f.read_text()); rep["version"] = v; f.write_text(json.dumps(rep))
        md = self.run_summary()
        self.assertIn('<td><a href="https://github.com/owner/rel/releases/tag/v1.2.0">v1.2.0</a></td>', self.row(md, "rel"))
        self.assertIn('<a href="https://github.com/owner/src/tree/' + "b" * 40 + '"><code>bbbbbbb</code></a>', self.row(md, "src"))
        self.assertIn("</a></td><td>–</td>", self.row(md, "bad"))
        self.assertNotIn("<script>", md)

    def test_baseline_problems_shown(self):
        self.add("p", problems=[{"fingerprint": "abc", "problem": "expired on 2026-01-01"}])
        md = self.run_summary()
        self.assertIn("expired on 2026-01-01", md)


    # Enriched findings

    def enriched(self, rule="obf-decode-into-call", code="fetch(u)", origin=None, source=None):
        f = finding(rule, code=code)
        f["context"] = {"before": "const u = atob(x);\n", "match": code, "after": "\nnext();"}
        f["origin"] = origin
        if source:
            f["source"] = source
        return f

    def test_rule_explanation_and_context_shown(self):
        self.add("p", blocking=[self.enriched()])
        md = self.run_summary()
        self.assertIn("Detects:", md)
        self.assertIn("False positive when:", md)
        self.assertIn("const u = atob(x);", md)
        self.assertIn("<b>fetch(u)</b>", md)

    def test_unknown_rule_has_generic_explanation(self):
        self.add("p", blocking=[self.enriched(rule="threat-something-new")])
        self.assertIn("No explanation available", self.run_summary())

    def test_origin_shown_as_unverified_hint(self):
        self.add("p", blocking=[self.enriched(origin={"kind": "library", "name": "yaml@2.6.1",
                                                     "path": "node_modules/.pnpm/yaml@2.6.1/x.js"})])
        md = self.run_summary()
        self.assertIn("yaml@2.6.1", md)
        self.assertIn("unverified", md)

    def test_source_link_rendered(self):
        url = "https://github.com/owner/p/blob/" + "a" * 40 + "/src/x.ts#L3"
        self.add("p", blocking=[self.enriched(origin={"kind": "plugin", "name": None, "path": "src/x.ts"},
                                              source={"path": "src/x.ts", "line": 3, "url": url, "how": "origin"})])
        md = self.run_summary()
        self.assertIn('<a href="https://github.com/owner/p/blob/', md)
        self.assertIn("src/x.ts:3", md)
        self.assertIn("repository at the scanned commit", md)

    def test_source_link_without_line_says_so(self):
        url = "https://github.com/owner/p/blob/" + "a" * 40 + "/src/x.ts"
        self.add("p", blocking=[self.enriched(origin={"kind": "plugin", "name": None, "path": "src/x.ts"},
                                              source={"path": "src/x.ts", "line": None, "url": url})])
        self.assertIn("line not unique", self.run_summary())

    def test_text_search_link_is_labelled(self):
        url = "https://github.com/owner/p/blob/" + "a" * 40 + "/src/x.ts#L3"
        self.add("p", blocking=[self.enriched(source={"path": "src/x.ts", "line": 3, "url": url, "how": "search"})])
        self.assertIn("found by text search", self.run_summary())

    def test_foreign_source_url_is_not_linked(self):
        self.add("p", blocking=[self.enriched(source={"path": "x", "line": 1, "url": "javascript:alert(1)"})])
        md = self.run_summary()
        self.assertNotIn("javascript:", md)

    def test_source_url_is_escaped(self):
        url = 'https://github.com/owner/p/blob/x/"><script>.ts'
        self.add("p", blocking=[self.enriched(source={"path": "x", "line": 1, "url": url})])
        md = self.run_summary()
        self.assertNotIn("<script>", md)
        self.assertNotIn('">', md.split("Source:")[1].split("</a>")[0].replace('<a href="', "").replace('"><code>', ""))

    def test_accepted_findings_listed_with_reason(self):
        self.add("p")
        rep_file = self.reports / "report-p" / "report.json"
        rep = json.loads(rep_file.read_text())
        rep["accepted"] = {"f1": dict(finding("caido-make-executable"), reason="Download from <torproject.org>",
                                      owner="me", review_by="2027-05-01")}
        rep_file.write_text(json.dumps(rep))
        md = self.run_summary()
        self.assertIn("<summary>1 false positive</summary>", md)
        self.assertIn("Download from &lt;torproject.org&gt;", md)
        self.assertIn("2027-05-01", md)
        # Blocking, tolerated, false positives, info, baseline problems
        self.assertIn("<td>0</td><td>0</td><td>1</td><td>0</td><td>0</td>", self.row(md, "p"))

    def test_tolerated_plugin_is_yellow(self):
        self.add("risky"); self.add("clean"); self.add("fp")
        for pid, kind in (("risky", "tolerated"), ("fp", "false-positive")):
            f = self.reports / f"report-{pid}" / "report.json"
            rep = json.loads(f.read_text())
            rep["accepted"] = {"f1": dict(finding("caido-make-executable"), reason="<b>x</b>", owner="me",
                                          review_by="2027-05-01", kind=kind)}
            f.write_text(json.dumps(rep))
        md = self.run_summary()
        self.assertIn("🟡 tolerated", self.row(md, "risky"))
        self.assertIn("<summary>1 tolerated</summary>", self.row(md, "risky"))
        self.assertNotIn("false positive", self.row(md, "risky"))
        self.assertIn("<summary>1 false positive</summary>", self.row(md, "fp"))
        self.assertIn("&lt;b&gt;x&lt;/b&gt;", md)
        self.assertIn("🟢 ok", self.row(md, "fp"))
        self.assertIn("1 tolerated", md)
        table = md[md.index("<table>"):]
        self.assertLess(table.index("owner/risky"), table.index("owner/clean"))

    def test_further_locations_shown(self):
        f = self.enriched()
        f["also"] = [{"where": "backend/index.js:9", "source": {"path": "src/x.ts", "line": 7,
                      "url": "https://github.com/owner/p/blob/" + "a" * 40 + "/src/x.ts#L7"}}]
        self.add("p", blocking=[f])
        md = self.run_summary()
        self.assertIn("Same code also @ <code>backend/index.js:9</code>", md)
        self.assertIn("src/x.ts:7", md)

    def test_table_has_no_blank_line(self):
        # A blank line ends the HTML block; the rest of the table would appear as text
        f = self.enriched(code="a\n\n\nb")
        f["context"]["before"] = "x\n\n\ny\n"
        self.add("p", blocking=[f])
        self.add("q")
        rep_file = self.reports / "report-q" / "report.json"
        rep = json.loads(rep_file.read_text())
        rep["accepted"] = {"f": dict(finding("r"), reason="a\n\nb", owner="o", review_by="2027-01-01")}
        rep["baseline_problems"] = [{"fingerprint": "x", "problem": "p\n\nq"}]
        rep_file.write_text(json.dumps(rep))
        md = self.run_summary()
        table = md[md.index("<table>"):md.index("</table>")]
        self.assertNotIn("\n\n", table)

    def test_accepted_findings_show_code_collapsed(self):
        self.add("p")
        rep_file = self.reports / "report-p" / "report.json"
        rep = json.loads(rep_file.read_text())
        f = self.enriched(code="atob(x)")
        rep["accepted"] = {"f1": dict(f, reason="ok", owner="me", review_by="2027-05-01")}
        rep_file.write_text(json.dumps(rep))
        md = self.run_summary()
        self.assertIn("<details><summary>Code</summary><pre>const u = atob(x);", md)
        self.assertIn("<b>atob(x)</b>", md)

    def test_library_origin_links_npm_package(self):
        cases = {"yaml@2.6.1": "https://www.npmjs.com/package/yaml/v/2.6.1",
                 "@vue/shared@3.4.37": "https://www.npmjs.com/package/@vue/shared/v/3.4.37",
                 "zod": "https://www.npmjs.com/package/zod"}
        for name, url in cases.items():
            self.assertIn(f'<a href="{url}">', summary.npm_link(name))
        for bad in ('x"><script>', "../x@1", "a@1 2", ""):
            self.assertIsNone(summary.npm_link(bad), bad)
        self.add("p", blocking=[self.enriched(origin={"kind": "library", "name": "yaml@2.6.1",
                                                     "path": "node_modules/.pnpm/yaml@2.6.1/x.js"})])
        md = self.run_summary()
        self.assertIn('<a href="https://www.npmjs.com/package/yaml/v/2.6.1">', md)
        self.assertIn("no line link", md)

    def test_bundle_code_without_source_says_why(self):
        self.add("p", blocking=[self.enriched()])
        self.assertIn("only in the built bundle", self.run_summary())

    def test_identical_code_in_other_plugins_counted(self):
        shared = self.enriched(code="bytes[i]")
        self.add("a", blocking=[shared]); self.add("b", blocking=[shared]); self.add("c", blocking=[shared])
        md = self.run_summary()
        self.assertIn("Same match in 2 other plugins: b, c", md)

    def test_shared_compares_full_match_not_excerpt(self):
        a = self.enriched(code="eval(" + "x" * 295); a["match_sha256"] = "1" * 64
        b = dict(a, match_sha256="2" * 64)
        self.add("a", blocking=[a]); self.add("b", blocking=[b])
        self.assertNotIn("Same match", self.run_summary())

    def test_baseline_entry_snippet_contains_fingerprint(self):
        self.add("p", blocking=[self.enriched()])
        md = self.run_summary()
        self.assertIn("&quot;fingerprint&quot;: &quot;b0&quot;", md)
        self.assertIn("&quot;reason&quot;: &quot;&quot;", md)

    def test_context_is_escaped(self):
        f = self.enriched(code="<script>alert(1)</script>")
        f["context"]["before"] = "<img src=x onerror=alert(1)>\n## x"
        self.add("p", blocking=[f])
        md = self.run_summary()
        self.assertNotIn("<img", md)
        self.assertNotIn("<script>", md)


if __name__ == "__main__":
    unittest.main()
