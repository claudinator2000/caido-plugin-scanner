"""Tests for scripts/findings.py (fingerprints, baseline gate, incomplete scans)."""
import contextlib, datetime, importlib.util, io, json, os, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("findings", ROOT / "scripts" / "findings.py")
findings = importlib.util.module_from_spec(spec)
spec.loader.exec_module(findings)

TODAY = datetime.date(2026, 11, 2)
GUARDDOG = {"errors": {}, "risks": [{"threat_rule": "threat-process-download-exec", "severity": "high",
                                     "threat_location": "backend/index.js:5", "file_path": "backend/index.js",
                                     "threat_match": "fetch(\"https:"}]}
OSV = {"results": [{"packages": [{"package": {"name": "evil-pkg", "version": "1.0.0"},
                                  "vulnerabilities": [{"id": "MAL-2026-1"}, {"id": "GHSA-xxxx-yyyy-zzzz"}]}]}]}


def semgrep(path, line, rule, severity):
    return {"check_id": f"rules.{rule}", "path": path,
            "start": {"line": line, "col": 1}, "end": {"line": line, "col": 80},
            "extra": {"severity": severity, "lines": "requires login"}}


def accept(candidate, **fields):
    entry = {"reason": "reviewed, harmless", "owner": "reviewer", "review_by": "2027-05-01"}
    entry.update(fields)
    return {"accepted": [dict(e, **entry) for e in candidate["accepted"]]}


class FindingsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        (self.d / "target").mkdir()
        self.js = self.d / "target" / "a.js"
        self.js.write_text("x\nfetch(u);\n")
        # Files for the GuardDog and Semgrep error fixtures
        (self.d / "target" / "backend").mkdir()
        (self.d / "target" / "backend" / "index.js").write_text('fetch("https://x.invalid");\n')
        (self.d / "target" / "frontend").mkdir()
        self.bundle = self.d / "target" / "frontend" / "index.js"
        self.bundle.write_text("var a = 1;\n")

    def tearDown(self):
        self.tmp.cleanup()

    def run_gate(self, sg_results=(), baseline=None, gd=GUARDDOG, osv=OSV, sg_errors=(), raw=None, inv=None,
                 source=None):
        files = {"gd.json": gd, "sg.json": {"results": list(sg_results), "errors": list(sg_errors)},
                 "osv.json": osv, "inv.json": inv or {"files": [], "findings": [], "workflow_code": []}}
        for name, data in files.items():
            (self.d / name).write_text(json.dumps(data))
        for name, text in (raw or {}).items():
            (self.d / name).write_text(text)
        base = self.d / "base.json"
        if baseline is not None:
            base.write_text(json.dumps(baseline))
        out = self.d / "report.json"
        out.unlink(missing_ok=True)
        with contextlib.redirect_stdout(io.StringIO()):
            extra = (str(self.d / "src"), str(source), "owner/repo", "release") if source else ()
            rc = findings.main("demo", *(str(self.d / n) for n in files), str(base), str(out), *extra,
                               today=TODAY, target_root=str(self.d / "target"))
        return rc, (json.loads(out.read_text()) if out.exists() else None)

    def warning(self, line=2):
        return semgrep(str(self.js), line, "obf-dynamic-code-exec", "WARNING")

    # Gate

    def test_without_baseline_blocks_on_warning_error_and_guarddog(self):
        rc, rep = self.run_gate([self.warning(),
                                 semgrep(str(self.js), 2, "caido-hardcoded-external-url", "INFO")])
        self.assertEqual(rc, 1)
        rules = sorted(v["rule"] for v in rep["new_blocking"].values())
        self.assertEqual(rules, ["MAL-2026-1", "obf-dynamic-code-exec", "threat-process-download-exec"])
        info = sorted(v["rule"] for v in rep["new_info"].values())
        self.assertEqual(info, ["GHSA-xxxx-yyyy-zzzz", "caido-hardcoded-external-url"])

    def test_reviewed_baseline_silences_known_findings(self):
        _, rep = self.run_gate([self.warning()])
        rc, rep2 = self.run_gate([self.warning()], baseline=accept(rep["baseline_candidate"]))
        self.assertEqual(rc, 0)
        self.assertEqual(rep2["new_blocking"], {})
        self.assertEqual(rep2["baseline_problems"], [])

    def test_any_file_change_requires_new_review(self):
        # Even a pure move: the fingerprint depends on the file content
        _, rep = self.run_gate([self.warning()])
        self.js.write_text("x\n\n\nfetch(u);\n")
        rc, _ = self.run_gate([self.warning(line=4)], baseline=accept(rep["baseline_candidate"]))
        self.assertEqual(rc, 1)

    def test_changed_code_is_new(self):
        _, rep = self.run_gate([self.warning()])
        self.js.write_text("x\nfetch(other);\n")
        rc, _ = self.run_gate([self.warning()], baseline=accept(rep["baseline_candidate"]))
        self.assertEqual(rc, 1)

    def test_matches_beyond_column_400_keep_distinct_code(self):
        # Minified bundles: match far to the right in a line
        pad = "x" * 500
        self.js.write_text(pad + "fetch(a);fetch(b);\n")
        first = semgrep(str(self.js), 1, "obf-decode-into-call", "WARNING")
        first["start"]["col"], first["end"]["col"] = 501, 509
        second = semgrep(str(self.js), 1, "obf-decode-into-call", "WARNING")
        second["start"]["col"], second["end"]["col"] = 510, 518
        _, rep = self.run_gate([first, second])
        codes = sorted(v["code"] for v in rep["all"].values() if v["tool"] == "semgrep")
        self.assertEqual(codes, ["fetch(a)", "fetch(b)"])

    def test_spans_use_byte_offsets_after_multibyte_text(self):
        # Semgrep counts columns and offsets in bytes; "é" is two bytes long in UTF-8
        prefix = "/* " + "é" * 100 + " */ "
        line = prefix + "fetch(a);fetch(b);"
        self.js.write_text(line + "\n", encoding="utf-8")
        base = len(prefix.encode())
        hits = []
        for start, end in ((base, base + 8), (base + 9, base + 17)):
            x = semgrep(str(self.js), 1, "obf-dynamic-code-exec", "WARNING")
            x["start"] = {"line": 1, "col": start + 1, "offset": start}
            x["end"] = {"line": 1, "col": end + 1, "offset": end}
            hits.append(x)
        _, rep = self.run_gate(hits)
        codes = sorted(v["code"] for v in rep["all"].values() if v["tool"] == "semgrep")
        self.assertEqual(codes, ["fetch(a)", "fetch(b)"])

    def test_taint_fingerprint_changes_with_source(self):
        # Same sink fetch(u), different decoded origin: needs a new review
        def fingerprint(source):
            self.js.write_text(f'const u = atob("{source}");\nfetch(u);\n')
            x = semgrep(str(self.js), 2, "obf-decode-into-call", "WARNING")
            x["start"] = {"line": 2, "col": 1, "offset": 28}
            x["end"] = {"line": 2, "col": 9, "offset": 36}
            _, rep = self.run_gate([x])
            return [k for k, v in rep["all"].items() if v["tool"] == "semgrep"]
        self.assertNotEqual(fingerprint("aHR0cHM6Ly9hLmludmFsaWQ="), fingerprint("aHR0cHM6Ly9iLmludmFsaWQ="))

    def test_eval_fingerprint_changes_with_payload_definition(self):
        # Match stays eval(payload), the executed string changes
        def fingerprint(payload):
            prefix = f'const payload = "{payload}";\n'
            self.js.write_text(prefix + "eval(payload);\n")
            x = semgrep(str(self.js), 2, "obf-dynamic-code-exec", "WARNING")
            start = len(prefix.encode())
            x["start"] = {"line": 2, "col": 1, "offset": start}
            x["end"] = {"line": 2, "col": 14, "offset": start + 13}
            _, rep = self.run_gate([x])
            return [k for k, v in rep["all"].items() if v["tool"] == "semgrep"]
        self.assertNotEqual(fingerprint("1 + 1"), fingerprint("globalThis.executed = true"))

    def test_guarddog_fingerprint_changes_with_file(self):
        def fingerprint():
            _, rep = self.run_gate(osv={"results": []})
            return [k for k, v in rep["all"].items() if v["tool"] == "guarddog"]
        before = fingerprint()
        (self.d / "target" / "backend" / "index.js").write_text('fetch("https://x.invalid", {body: secrets});\n')
        self.assertNotEqual(before, fingerprint())

    def test_finding_for_missing_file_is_incomplete(self):
        x = semgrep(str(self.d / "target" / "gone.js"), 1, "obf-dynamic-code-exec", "WARNING")
        rc, rep = self.run_gate([x])
        self.assertEqual(rc, 2)
        self.assertIsNone(rep)

    def test_whitespace_inside_match_changes_fingerprint(self):
        # A line break ends the comment in the template literal: different behaviour
        def fingerprint(body):
            code = "eval(`" + body + "`)"
            self.js.write_text(code + "\n")
            x = semgrep(str(self.js), 1, "obf-dynamic-code-exec", "WARNING")
            x["start"] = {"line": 1, "col": 1, "offset": 0}
            x["end"] = {"line": code.count("\n") + 1, "col": 1, "offset": len(code.encode())}
            _, rep = self.run_gate([x])
            return [k for k, v in rep["all"].items() if v["tool"] == "semgrep"]
        self.assertNotEqual(fingerprint("// reviewed comment globalThis.executed = true;"),
                            fingerprint("// reviewed comment\nglobalThis.executed = true;"))

    def test_long_matches_differing_after_300_chars_are_distinct(self):
        head = "fetch(u, {headers: {" + ", ".join(f"h{i}: v{i}" for i in range(60)) + "}, body: "
        self.assertGreater(len(head), 300)
        self.js.write_text(head + "a});\n" + head + "proxyTraffic});\n")
        first = semgrep(str(self.js), 1, "obf-decode-into-call", "WARNING")
        first["end"] = {"line": 1, "col": len(head) + 4}
        second = semgrep(str(self.js), 2, "obf-decode-into-call", "WARNING")
        second["end"] = {"line": 2, "col": len(head) + 15}
        _, rep = self.run_gate([first, second])
        self.assertEqual(len([v for v in rep["all"].values() if v["tool"] == "semgrep"]), 2)
        # Report excerpt stays shortened
        self.assertTrue(all(len(v.get("code", "")) <= 300 for v in rep["all"].values()))

    def test_multiline_match_is_extracted(self):
        self.js.write_text("a;fetch(\n  u,\n  o);b\n")
        x = semgrep(str(self.js), 1, "obf-decode-into-call", "WARNING")
        x["start"], x["end"] = {"line": 1, "col": 3}, {"line": 3, "col": 5}
        self.assertEqual(findings.norm(findings.src_lines(x)), "fetch( u, o)")

    def test_target_prefix_does_not_change_fingerprint(self):
        self.assertEqual(findings.rel("target/backend/index.js"), "backend/index.js")
        self.assertEqual(findings.rel("backend/index.js"), "backend/index.js")

    # Baseline entries are exceptions: reason, owner, review date

    def test_unreviewed_candidate_does_not_suppress(self):
        _, rep = self.run_gate([self.warning()])
        rc, rep2 = self.run_gate([self.warning()], baseline=rep["baseline_candidate"])
        self.assertEqual(rc, 1)
        self.assertTrue(all("missing" in p["problem"] for p in rep2["baseline_problems"]))

    def test_expired_entry_does_not_suppress(self):
        _, rep = self.run_gate([self.warning()])
        rc, rep2 = self.run_gate([self.warning()],
                                 baseline=accept(rep["baseline_candidate"], review_by="2026-11-01"))
        self.assertEqual(rc, 1)
        self.assertTrue(all("expired" in p["problem"] for p in rep2["baseline_problems"]))

    def test_risk_accepted_entry_suppresses_with_basis(self):
        _, rep = self.run_gate([self.warning()])
        rc, rep2 = self.run_gate([self.warning()], baseline=accept(rep["baseline_candidate"], kind="risk-accepted",
                                                                  basis="plugin-purpose"))
        self.assertEqual(rc, 0)
        self.assertEqual({(v["kind"], v["basis"]) for v in rep2["accepted"].values()},
                         {("risk-accepted", "plugin-purpose")})

    def test_risk_accepted_without_valid_basis_does_not_suppress(self):
        _, rep = self.run_gate([self.warning()])
        for fields in ({"kind": "risk-accepted"}, {"kind": "risk-accepted", "basis": "because"},
                       {"kind": "fine"}):
            with self.subTest(fields=fields):
                rc, rep2 = self.run_gate([self.warning()], baseline=accept(rep["baseline_candidate"], **fields))
                self.assertEqual(rc, 1)
                self.assertTrue(rep2["baseline_problems"])

    def test_entry_without_kind_is_a_false_positive(self):
        _, rep = self.run_gate([self.warning()])
        _, rep2 = self.run_gate([self.warning()], baseline=accept(rep["baseline_candidate"]))
        self.assertEqual({v["kind"] for v in rep2["accepted"].values()}, {"false-positive"})

    def test_stale_entry_is_reported(self):
        _, rep = self.run_gate([self.warning()])
        rc, rep2 = self.run_gate([], baseline=accept(rep["baseline_candidate"]))
        self.assertEqual(rc, 0)
        self.assertEqual(len(rep2["baseline_stale"]), 1)

    def test_unreadable_baseline_is_incomplete(self):
        rc, rep = self.run_gate([self.warning()], raw={"base.json": "{"}, baseline=None)
        self.assertEqual(rc, 2)
        self.assertIsNone(rep)

    # Incomplete scans are not a passed scan

    def test_guarddog_without_risks_is_incomplete(self):
        failed = {"package": "target/", "issues": 0, "errors": {"download-package": "not supported"}}
        rc, rep = self.run_gate([self.warning()], gd=failed)
        self.assertEqual(rc, 2)
        self.assertIsNone(rep)

    def test_missing_or_empty_output_is_incomplete(self):
        for name in ("gd.json", "sg.json", "osv.json"):
            with self.subTest(name=name):
                rc, rep = self.run_gate([self.warning()], raw={name: ""})
                self.assertEqual(rc, 2)
                self.assertIsNone(rep)

    def test_guarddog_rule_error_blocks(self):
        rc, rep = self.run_gate(gd={"errors": {"semgrep": "crashed"}, "risks": []}, osv={"results": []})
        self.assertEqual(rc, 1)
        self.assertEqual([v["rule"] for v in rep["new_blocking"].values()], ["scan-error:semgrep"])

    def test_accepted_guarddog_error_does_not_cover_changed_target(self):
        failed = {"errors": {"semgrep": "crashed"}, "risks": []}
        _, rep = self.run_gate(gd=failed, osv={"results": []})
        self.js.write_text("x\nfetch(evil);\n")
        rc, _ = self.run_gate(gd=failed, osv={"results": []}, baseline=accept(rep["baseline_candidate"]))
        self.assertEqual(rc, 1)

    def test_accepted_guarddog_error_holds_for_unchanged_target(self):
        failed = {"errors": {"semgrep": "crashed"}, "risks": []}
        _, rep = self.run_gate(gd=failed, osv={"results": []})
        rc, _ = self.run_gate(gd=failed, osv={"results": []}, baseline=accept(rep["baseline_candidate"]))
        self.assertEqual(rc, 0)

    def test_semgrep_partial_parsing_error_blocks(self):
        # Semgrep 1.182.1 returns the type here as a list: ["PartialParsing", [ranges]]
        partial = {"type": ["PartialParsing", [{"path": str(self.bundle),
                                                "start": {"line": 3, "col": 1}, "end": {"line": 3, "col": 9}}]],
                   "level": "warn", "path": str(self.bundle), "message": "Syntax error"}
        rc, rep = self.run_gate(gd={"errors": {}, "risks": []}, osv={"results": []}, sg_errors=[partial])
        self.assertEqual(rc, 1)
        self.assertEqual([v["rule"] for v in rep["new_blocking"].values()], ["scan-error:PartialParsing"])

    def test_semgrep_timeout_blocks_until_accepted(self):
        timeout = {"type": "Timeout", "level": "warn", "path": str(self.bundle),
                   "rule_id": "rules.caido-traffic-to-network", "message": "Timeout when running ..."}
        rc, rep = self.run_gate(gd={"errors": {}, "risks": []}, osv={"results": []}, sg_errors=[timeout])
        self.assertEqual(rc, 1)
        self.assertEqual([v["rule"] for v in rep["new_blocking"].values()],
                         ["scan-error:Timeout:caido-traffic-to-network"])
        rc, _ = self.run_gate(gd={"errors": {}, "risks": []}, osv={"results": []}, sg_errors=[timeout],
                              baseline=accept(rep["baseline_candidate"]))
        self.assertEqual(rc, 0)

    def test_accepted_timeout_does_not_cover_changed_file(self):
        timeout = {"type": "Timeout", "level": "warn", "path": str(self.bundle),
                   "rule_id": "rules.caido-traffic-to-network", "message": "Timeout when running ..."}
        empty = {"gd": {"errors": {}, "risks": []}, "osv": {"results": []}}
        _, rep = self.run_gate(sg_errors=[timeout], **empty)
        self.bundle.write_text("var a = 1; fetch(evil);\n")
        rc, _ = self.run_gate(sg_errors=[timeout], baseline=accept(rep["baseline_candidate"]), **empty)
        self.assertEqual(rc, 1)


    # Enrichment for the report: context and origin in the bundle

    def test_semgrep_finding_has_context_and_library_origin(self):
        src = ("// node_modules/.pnpm/yaml@2.6.1/node_modules/yaml/dist/schema.js\n"
               "var a = 1;\nconst u = atob(x);\nfetch(u);\nvar b = 2;\n")
        self.js.write_text(src)
        start = src.index("fetch(u)")
        x = semgrep(str(self.js), 4, "obf-decode-into-call", "WARNING")
        x["start"] = {"line": 4, "col": 1, "offset": start}
        x["end"] = {"line": 4, "col": 9, "offset": start + 8}
        _, rep = self.run_gate([x])
        v = next(v for v in rep["all"].values() if v["tool"] == "semgrep")
        self.assertEqual(v["context"]["match"], "fetch(u)")
        self.assertIn("const u = atob(x);", v["context"]["before"])
        self.assertIn("var b = 2;", v["context"]["after"])
        self.assertEqual(v["origin"], {"kind": "library", "name": "yaml@2.6.1",
                                       "path": "node_modules/.pnpm/yaml@2.6.1/node_modules/yaml/dist/schema.js"})

    def test_plugin_code_origin_and_none(self):
        src = "// packages/backend/src/index.ts\neval(x);\n"
        self.js.write_text(src)
        x = semgrep(str(self.js), 2, "obf-dynamic-code-exec", "WARNING")
        start = src.index("eval")
        x["start"] = {"line": 2, "col": 1, "offset": start}
        x["end"] = {"line": 2, "col": 8, "offset": start + 7}
        _, rep = self.run_gate([x])
        v = next(v for v in rep["all"].values() if v["tool"] == "semgrep")
        self.assertEqual(v["origin"]["kind"], "plugin")
        self.js.write_text("eval(x);\n")
        x["start"] = {"line": 1, "col": 1, "offset": 0}
        x["end"] = {"line": 1, "col": 8, "offset": 7}
        _, rep = self.run_gate([x])
        v = next(v for v in rep["all"].values() if v["tool"] == "semgrep")
        self.assertIsNone(v["origin"])

    def test_library_name_from_plain_and_scoped_paths(self):
        self.assertEqual(findings.library_of("node_modules/zod/v4/core/errors.js"), "zod")
        self.assertEqual(findings.library_of("node_modules/.pnpm/@vue+shared@3.5.13/node_modules/@vue/shared/x.js"),
                         "@vue/shared@3.5.13")
        self.assertEqual(findings.library_of("node_modules/@primevue/core/x.js"), "@primevue/core")

    def test_inventory_findings_block_and_bind_to_file_hash(self):
        finding = {"rule": "inventory-native-binary", "path": "bin/tool", "sha256": "a" * 64, "kind": "elf", "size": 64}
        rc, rep = self.run_gate(osv={"results": []}, gd={"errors": {}, "risks": []},
                                inv={"files": [], "findings": [finding], "workflow_code": []})
        self.assertEqual(rc, 1)
        (key, v), = rep["new_blocking"].items()
        self.assertEqual((v["tool"], v["rule"], v["where"]), ("inventory", "inventory-native-binary", "bin/tool"))
        accepted = {"accepted": [{"fingerprint": key, "reason": "reviewed", "owner": "o", "review_by": "2027-01-01"}]}
        rc, _ = self.run_gate(osv={"results": []}, gd={"errors": {}, "risks": []}, baseline=accepted,
                              inv={"files": [], "findings": [finding], "workflow_code": []})
        self.assertEqual(rc, 0)
        # Different file at the same path: the exception does not apply
        changed = dict(finding, sha256="b" * 64)
        rc, _ = self.run_gate(osv={"results": []}, gd={"errors": {}, "risks": []}, baseline=accepted,
                              inv={"files": [], "findings": [changed], "workflow_code": []})
        self.assertEqual(rc, 1)

    def test_missing_inventory_is_incomplete(self):
        rc, rep = self.run_gate(raw={"inv.json": "{}"})
        self.assertEqual(rc, 2)
        self.assertIsNone(rep)

    def test_guarddog_finding_has_line_context(self):
        _, rep = self.run_gate(osv={"results": []})
        v = next(v for v in rep["all"].values() if v["tool"] == "guarddog")
        self.assertIn('fetch("https:', v["context"]["match"])

    def test_guarddog_context_prefers_reported_line(self):
        # Same signature twice in the search window: context and origin of the reported match
        src = 'fetch("https://first");\n// node_modules/lib-x/index.js\nfetch("https://second");\n'
        self.js.write_text(src)
        ctx, origin = findings.guarddog_context(self.js, "index.js:3", 'fetch("https:')
        self.assertTrue(ctx["after"].startswith("//second"))
        self.assertEqual(origin["name"], "lib-x")
        # If the match is not on the reported line, the nearest one in the window applies
        ctx, _ = findings.guarddog_context(self.js, "index.js:2", 'fetch("https:')
        self.assertTrue(ctx["after"].startswith("//second"))

    def test_full_match_digest_recorded(self):
        # Same first 300 characters, different rest: different digests
        head = "eval(" + "a" * 400
        digests = []
        for tail in ("1)", "2)"):
            src = head + tail + "\n"
            self.js.write_text(src)
            x = semgrep(str(self.js), 1, "obf-dynamic-code-exec", "WARNING")
            x["start"] = {"line": 1, "col": 1, "offset": 0}
            x["end"] = {"line": 1, "col": len(src), "offset": len(src) - 1}
            _, rep = self.run_gate([x])
            v = next(v for v in rep["all"].values() if v["tool"] == "semgrep")
            digests.append(v["match_sha256"])
        self.assertNotEqual(digests[0], digests[1])

    def test_identical_match_twice_in_file_keeps_both_locations(self):
        self.js.write_text("x\nfetch(u);\ny\nfetch(u);\n")
        rc, rep = self.run_gate([self.warning(2), self.warning(4)], gd={"errors": {}, "risks": []},
                                osv={"results": []})
        self.assertEqual(len(rep["all"]), 1)
        v = next(iter(rep["all"].values()))
        self.assertTrue(v["where"].endswith("a.js:2"))
        self.assertEqual(len(v["also"]), 1)
        self.assertTrue(v["also"][0]["where"].endswith("a.js:4"))

    # One alarm per finding

    def scanned(self, commit="a" * 40, sha=None):
        """source.txt (and sha256.txt) as written by fetch-target.sh."""
        d = self.d / "scan"
        d.mkdir(exist_ok=True)
        (d / "source.txt").write_text(f"ref v1\ncommit {commit}\n")
        if sha:
            (d / "sha256.txt").write_text(f"{sha}  pkg.zip\n")
        return d / "source.txt"

    def gate_with_known(self, fps, state, source, **kw):
        os.environ["KNOWN_BLOCKING"], os.environ["KNOWN_STATE"] = json.dumps(fps), state
        try:
            return self.run_gate([self.warning()], gd={"errors": {}, "risks": []}, osv={"results": []},
                                 source=source, **kw)
        finally:
            del os.environ["KNOWN_BLOCKING"], os.environ["KNOWN_STATE"]

    def test_known_blocking_does_not_fail_again(self):
        _, first = self.run_gate([self.warning()], gd={"errors": {}, "risks": []}, osv={"results": []})
        fps = sorted(first["new_blocking"])
        head = "repo=o/a;head=" + "a" * 40
        rc, rep = self.gate_with_known(fps, head, self.scanned())
        self.assertEqual(rc, 0)
        self.assertEqual(sorted(rep["new_blocking"]), fps)
        self.assertEqual(rep["known_blocking"], fps)
        # A further finding alarms
        os.environ["KNOWN_BLOCKING"], os.environ["KNOWN_STATE"] = json.dumps(fps), head
        try:
            rc, _ = self.run_gate([self.warning()], osv={"results": []}, source=self.scanned())
        finally:
            del os.environ["KNOWN_BLOCKING"], os.environ["KNOWN_STATE"]
        self.assertEqual(rc, 1)

    def test_report_names_scanned_version(self):
        _, rep = self.run_gate([self.warning()], source=self.scanned())
        self.assertEqual(rep["version"], {"tag": "v1", "commit": "a" * 40})
        (self.d / "scan" / "source.txt").write_text("ref v1:evil\ncommit " + "a" * 40 + "\n")
        self.assertEqual(findings.scanned_version(self.d / "scan" / "source.txt", "release"), {"commit": "a" * 40})
        self.assertEqual(findings.scanned_version(self.d / "scan" / "source.txt", "source"), {"commit": "a" * 40})
        (self.d / "scan" / "source.txt").write_text("ref HEAD\ncommit nothex\n")
        self.assertIsNone(findings.scanned_version(self.d / "scan" / "source.txt", "source"))
        self.assertIsNone(findings.scanned_version(self.d / "missing.txt", "source"))

    def test_known_findings_only_for_the_scanned_state(self):
        _, first = self.run_gate([self.warning()], gd={"errors": {}, "risks": []}, osv={"results": []})
        fps = sorted(first["new_blocking"])
        release = "repo=o/a;asset=1;updated=2026-01-01T00:00:00Z;digest=sha256:" + "b" * 64 + ";tag=v1;commit=" + "a" * 40
        # Same state: commit and ZIP match
        self.assertEqual(self.gate_with_known(fps, release, self.scanned(sha="b" * 64))[0], 0)
        # Update between selection and scan: different ZIP, different commit, no source.txt
        self.assertEqual(self.gate_with_known(fps, release, self.scanned(sha="c" * 64))[0], 1)
        self.assertEqual(self.gate_with_known(fps, release, self.scanned(commit="d" * 40, sha="b" * 64))[0], 1)
        self.assertEqual(self.gate_with_known(fps, "repo=o/a;head=" + "e" * 40, self.scanned())[0], 1)
        self.assertEqual(self.gate_with_known(fps, "", self.scanned())[0], 1)
        os.environ["KNOWN_BLOCKING"] = json.dumps(fps)
        try:
            rc, _ = self.run_gate([self.warning()], gd={"errors": {}, "risks": []}, osv={"results": []})
        finally:
            del os.environ["KNOWN_BLOCKING"]
        self.assertEqual(rc, 1)

    def test_invalid_known_list_alarms(self):
        for raw in ("not json", '{"a": 1}', '["../x"]', '[1]'):
            self.assertEqual(findings.known_blocking(raw), set())
        os.environ["KNOWN_BLOCKING"], os.environ["KNOWN_STATE"] = "garbage", "repo=o/a;head=" + "a" * 40
        try:
            rc, _ = self.run_gate([self.warning()], gd={"errors": {}, "risks": []}, osv={"results": []},
                                  source=self.scanned())
        finally:
            del os.environ["KNOWN_BLOCKING"], os.environ["KNOWN_STATE"]
        self.assertEqual(rc, 1)

    # Accepted findings in the report
    def test_accepted_findings_carry_reason(self):
        _, first = self.run_gate([self.warning()])
        _, rep = self.run_gate([self.warning()], baseline=accept(first["baseline_candidate"]))
        self.assertEqual(set(rep["accepted"]), set(first["all"]))
        entry = next(iter(rep["accepted"].values()))
        self.assertEqual((entry["reason"], entry["owner"], entry["review_by"]),
                         ("reviewed, harmless", "reviewer", "2027-05-01"))
        self.assertIn("rule", entry)

    def test_expired_entry_is_not_listed_as_accepted(self):
        _, first = self.run_gate([self.warning()])
        _, rep = self.run_gate([self.warning()], baseline=accept(first["baseline_candidate"], review_by="2026-01-01"))
        self.assertEqual(rep["accepted"], {})

    def test_link_failure_does_not_fail_the_gate(self):
        (self.d / "source.txt").write_text("ref x\ncommit " + COMMIT + "\n")
        files = {"gd.json": GUARDDOG, "sg.json": {"results": [], "errors": []}, "osv.json": {"results": []},
                 "inv.json": {"files": [], "findings": [], "workflow_code": []}}
        for name, data in files.items():
            (self.d / name).write_text(json.dumps(data))
        out = self.d / "report.json"
        with contextlib.redirect_stdout(io.StringIO()):
            rc = findings.main("demo", *(str(self.d / n) for n in files), str(self.d / "none.json"), str(out),
                               str(self.d / "missing-src"), str(self.d / "missing.txt"), "owner/repo", "release",
                               today=TODAY, target_root=str(self.d / "target"))
        self.assertEqual(rc, 1)
        self.assertTrue(out.exists())


COMMIT = "a" * 40


class SourceLinkTest(unittest.TestCase):
    """Links into the source at the scanned commit (display only)."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.src = Path(self.tmp.name)
        (self.src / "packages/backend/src").mkdir(parents=True)
        (self.src / "packages/backend/src/download.ts").write_text(
            "import { chmod } from 'fs/promises';\n"
            "export const install = async (finalPath: string) => {\n"
            "  await chmod(finalPath, 0o755);\n"
            "};\n")
        (self.src / "packages/backend/src/notify.ts").write_text(
            "const test = () => {\n  const args = ['-v', path];\n  spawn(cmd, args, { shell: true });\n};\n"
            "const send = () => {\n  const args = ['-bulk', path];\n  spawn(cmd, args, { shell: true });\n};\n")

    def tearDown(self):
        self.tmp.cleanup()

    def link(self, finding, mode="release", repo="owner/repo", commit=COMMIT):
        found = {"k": finding}
        findings.add_source_links(found, str(self.src), commit, repo, mode)
        return found["k"].get("source")

    def bundle_finding(self, match, before="", origin_path="packages/backend/src/download.ts"):
        return {"origin": {"kind": "plugin", "name": None, "path": origin_path},
                "context": {"before": before, "match": match, "after": ""}}

    def test_transpiled_line_found_by_identifiers(self):
        src = self.link(self.bundle_finding("await chmod(finalPath, 493);"))
        self.assertEqual(src["line"], 3)
        self.assertEqual(src["url"], "https://github.com/owner/repo/blob/" + COMMIT
                         + "/packages/backend/src/download.ts#L3")

    def test_origin_relative_to_monorepo_package(self):
        src = self.link(self.bundle_finding("await chmod(finalPath, 493);", origin_path="src/download.ts"))
        self.assertEqual(src["path"], "packages/backend/src/download.ts")

    def test_repeated_line_resolved_by_preceding_code(self):
        f = self.bundle_finding("spawn(cmd, args, { shell: true });", before="const args = ['-bulk', path];\n",
                                origin_path="packages/backend/src/notify.ts")
        self.assertEqual(self.link(f)["line"], 7)

    def test_repeated_line_prefers_identical_preceding_line(self):
        # Both candidates contain all identifiers of the preceding line; only one verbatim
        (self.src / "packages/backend/src/notify.ts").write_text(
            "const a = () => {\n  const args = ['-v', '-bulk', path];\n  spawn(cmd, args, { shell: true });\n};\n"
            "const b = () => {\n  const args = ['-bulk', path];\n  spawn(cmd, args, { shell: true });\n};\n")
        f = self.bundle_finding("spawn(cmd, args, { shell: true });", before="const args = ['-bulk', path];\n",
                                origin_path="packages/backend/src/notify.ts")
        self.assertEqual(self.link(f)["line"], 7)

    def test_repeated_line_without_context_links_file_only(self):
        f = self.bundle_finding("spawn(cmd, args, { shell: true });", origin_path="packages/backend/src/notify.ts")
        src = self.link(f)
        self.assertIsNone(src["line"])
        self.assertNotIn("#L", src["url"])

    def test_missing_or_ambiguous_origin_file_has_no_link(self):
        self.assertIsNone(self.link(self.bundle_finding("x", origin_path="src/missing.ts")))
        (self.src / "other/src").mkdir(parents=True)
        (self.src / "other/src/download.ts").write_text("x\n")
        self.assertIsNone(self.link(self.bundle_finding("x", origin_path="src/download.ts")))

    def test_library_origin_has_no_link(self):
        f = {"origin": {"kind": "library", "name": "zod", "path": "node_modules/zod/x.js"},
             "context": {"before": "", "match": "await chmod(finalPath, 493);", "after": ""}}
        self.assertIsNone(self.link(f))

    def test_text_search_without_origin(self):
        f = {"context": {"before": "x = ", "match": "chmod(finalPath, 0o755)", "after": ";"}}
        src = self.link(f)
        self.assertEqual((src["path"], src["line"], src["how"]), ("packages/backend/src/download.ts", 3, "search"))

    def test_text_search_ambiguous_or_short_has_no_link(self):
        self.assertIsNone(self.link({"context": {"before": "", "match": "spawn(cmd, args, { shell: true });",
                                                 "after": ""}}))
        self.assertIsNone(self.link({"context": {"before": "", "match": "chmod(", "after": ""}}))

    def test_source_mode_links_scanned_path_and_line(self):
        f = {"file": "packages/backend/src/download.ts", "line": 3}
        src = self.link(f, mode="source")
        self.assertEqual(src["url"], "https://github.com/owner/repo/blob/" + COMMIT
                         + "/packages/backend/src/download.ts#L3")
        self.assertIsNone(self.link({"file": "__workflow_code__/x/node-1.js", "line": 1}, mode="source"))

    def test_invalid_repo_or_commit_gives_no_links(self):
        f = self.bundle_finding("await chmod(finalPath, 493);")
        self.assertIsNone(self.link(dict(f), repo="owner/repo/../x"))
        self.assertIsNone(self.link(dict(f), commit="HEAD"))

    def test_path_is_url_quoted(self):
        (self.src / "a b#c.ts").write_text("x\n")
        src = self.link({"file": "a b#c.ts", "line": 1}, mode="source")
        self.assertTrue(src["url"].endswith("/a%20b%23c.ts#L1"))


if __name__ == "__main__":
    unittest.main()
