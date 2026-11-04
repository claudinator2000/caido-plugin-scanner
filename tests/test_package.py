"""Tests for scripts/prepare_package.py (signature, ZIP pre-check, extraction, manifest).

All fixtures are created at runtime; signature tests generate Ed25519 keys with OpenSSL.
Every extraction test checks that nothing is created or changed outside the target.
"""
import base64, importlib.util, io, json, stat, struct, subprocess, tempfile, unittest, warnings, zipfile, zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("prepare_package", ROOT / "scripts" / "prepare_package.py")
pp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pp)

MANIFEST = {"id": "demo", "plugins": [
    {"kind": "backend", "id": "backend", "entrypoint": "backend/index.js"},
    {"kind": "frontend", "id": "frontend", "entrypoint": "frontend/index.js", "style": "frontend/index.css"}]}
GOOD = {"manifest.json": json.dumps(MANIFEST), "backend/index.js": "export {};\n",
        "frontend/index.js": "export {};\n", "frontend/index.css": "a{}\n"}


def build(entries):
    """entries: list of (name, data) or (ZipInfo, data)."""
    buf = io.BytesIO()
    with warnings.catch_warnings(), zipfile.ZipFile(buf, "w") as zf:
        warnings.simplefilter("ignore")  # duplicate names are intended here
        for name, data in entries:
            zf.writestr(name, data)
    return buf.getvalue()


def unix_info(name, mode):
    info = zipfile.ZipInfo(name)
    info.create_system = 3
    info.external_attr = mode << 16
    return info


LOCAL, CENTRAL = b"PK\x03\x04", b"PK\x01\x02"
# Field offsets: (method, flags, CRC, compressed size, size, name length, name)
FIELDS = {LOCAL: (8, 6, 14, 18, 22, 26, 30), CENTRAL: (10, 8, 16, 20, 24, 28, 46)}


def patch(data, name, method=None, flags=None, local_name=None, only=None, **sizes):
    """Changes fields of an entry directly in the ZIP bytes. sizes: central_crc, local_crc,
    central_csize, local_csize, central_usize, local_usize. only: "local"/"central"."""
    data = bytearray(data)
    raw = name.encode()
    for sig, (o_method, o_flags, o_crc, o_csize, o_usize, o_nlen, o_name) in FIELDS.items():
        where = "local" if sig == LOCAL else "central"
        pos = 0
        while (pos := data.find(sig, pos)) >= 0:
            n = struct.unpack_from("<H", data, pos + o_nlen)[0]
            if bytes(data[pos + o_name:pos + o_name + n]) == raw and only in (None, where):
                if method is not None:
                    struct.pack_into("<H", data, pos + o_method, method)
                if flags is not None:
                    struct.pack_into("<H", data, pos + o_flags, flags)
                if local_name is not None and sig == LOCAL:
                    data[pos + o_name:pos + o_name + n] = local_name.encode()
                for field, off in (("crc", o_crc), ("csize", o_csize), ("usize", o_usize)):
                    value = sizes.get(f"{where}_{field}")
                    if value is not None:
                        struct.pack_into("<I", data, pos + off, value)
            pos += 4
    return bytes(data)


def drop_central(data, name):
    """Removes the directory entry of name; the local data stays in place."""
    data = bytearray(data)
    raw = name.encode()
    pos = data.find(CENTRAL)
    while pos >= 0:
        n, m, k = struct.unpack_from("<HHH", data, pos + 28)
        length = 46 + n + m + k
        if bytes(data[pos + 46:pos + 46 + n]) == raw:
            del data[pos:pos + length]
            eocd = data.rfind(b"PK\x05\x06")
            count, size = struct.unpack_from("<HHI", data, eocd + 8)[0], struct.unpack_from("<I", data, eocd + 12)[0]
            struct.pack_into("<HHI", data, eocd + 8, count - 1, count - 1, size - length)
            return bytes(data)
        pos = data.find(CENTRAL, pos + 4)
    raise ValueError(name)


class Unseekable(io.RawIOBase):
    """Write target without seek: zipfile then writes data descriptors."""
    def __init__(self, target):
        self.target = target

    def writable(self):
        return True

    def write(self, b):
        return self.target.write(b)

    def flush(self):
        pass


class ExtractTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        self.work = self.d / "work"
        self.work.mkdir()
        # Canaries outside the target: must never change
        self.canary = self.d / "canary.txt"
        self.canary.write_text("unchanged")
        (self.work / "scripts").mkdir()
        (self.work / "scripts" / "findings.py").write_text("ORIGINAL")

    def tearDown(self):
        self.tmp.cleanup()

    def extract(self, data, expected_id=None, limits=pp.LIMITS):
        z = self.d / "pkg.zip"
        z.write_bytes(data)
        return pp.extract(z, self.work / "target", expected_id, limits)

    def assert_untouched(self, created=False):
        self.assertEqual(self.canary.read_text(), "unchanged")
        self.assertEqual((self.work / "scripts" / "findings.py").read_text(), "ORIGINAL")
        expected = {"scripts", "target"} if created else {"scripts"}
        self.assertEqual({p.name for p in self.work.iterdir()}, expected)

    def assert_rejected(self, data, expected_id=None, limits=pp.LIMITS):
        with self.assertRaises(pp.PackageError):
            self.extract(data, expected_id, limits)
        self.assert_untouched()

    def test_good_package_extracts_with_fixed_modes(self):
        info = unix_info("backend/index.js", stat.S_IFREG | 0o4777)
        data = build([("manifest.json", GOOD["manifest.json"]), (info, "export {};\n"),
                      ("frontend/", ""), ("frontend/index.js", "x"), ("frontend/index.css", "y")])
        self.extract(data, "demo")
        self.assert_untouched(created=True)
        mode = stat.S_IMODE((self.work / "target" / "backend" / "index.js").stat().st_mode)
        self.assertEqual(mode & 0o7111, 0)

    def test_path_attacks(self):
        for name in ("../escape.js", "a/../../escape.js", "/etc/x.js", "C:/x.js", "c:x.js",
                     "\\\\server\\share\\x.js", "a\\..\\x.js", "a//b.js", "./a.js", "a/./b.js",
                     "x" * 300 + ".js", "/".join(["d"] * 25) + "/x.js"):
            with self.subTest(name=name):
                self.assert_rejected(build([(name, "x")]))

    def test_nul_byte_in_name(self):
        data = build([("aXb.js", "x")]).replace(b"aXb.js", b"a\x00b.js")
        self.assert_rejected(data)

    def test_duplicate_and_colliding_names(self):
        cases = [[("a.js", "1"), ("a.js", "2")],
                 [("A.js", "1"), ("a.js", "2")],
                 [("\u00e9.js", "1"), ("e\u0301.js", "2")],
                 [("a", "file"), ("a/b.js", "x")],
                 [("a/b.js", "x"), ("a", "file")],
                 [("a/", ""), ("a", "file")]]
        for entries in cases:
            with self.subTest(entries=[n for n, _ in entries]):
                self.assert_rejected(build(entries))

    def test_symlink_and_special_files(self):
        link = unix_info("link", stat.S_IFLNK | 0o777)
        self.assert_rejected(build([(link, "../scripts"), ("link/findings.py", "PWNED")]))
        for mode in (stat.S_IFIFO, stat.S_IFCHR, stat.S_IFBLK, stat.S_IFSOCK):
            with self.subTest(mode=oct(mode)):
                self.assert_rejected(build([(unix_info("x", mode | 0o644), "")]))

    def test_encryption_and_methods(self):
        base = build([("a.js", "x" * 100)])
        self.assert_rejected(patch(base, "a.js", flags=0x1))          # ZipCrypto
        self.assert_rejected(patch(base, "a.js", method=99))          # WinZip-AES
        self.assert_rejected(patch(base, "a.js", method=12))          # bzip2: not allowed

    def test_compression_ratio_and_limits(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("bomb.js", b"\0" * (2 * pp.MiB))
        self.assert_rejected(buf.getvalue())
        small = dict(pp.LIMITS, entries=3, file_bytes=10, total_bytes=15)
        self.assert_rejected(build([(f"{i}.js", "x") for i in range(4)]), limits=small)
        self.assert_rejected(build([("a.js", "x" * 11)]), limits=small)
        self.assert_rejected(build([("a.js", "x" * 8), ("b.js", "x" * 8)]), limits=small)
        self.assert_rejected(build([("a.js", "x")]), limits=dict(pp.LIMITS, zip_bytes=10))

    def test_corrupt_crc_and_contradicting_headers(self):
        base = build([("a.js", "hello")])
        self.assert_rejected(patch(base, "a.js", central_crc=0))
        self.assert_rejected(patch(base, "a.js", local_name="b.js"))
        self.assert_rejected(b"PK\x03\x04 not a zip")

    def test_shortened_size_hides_no_content(self):
        # Codex finding: the directory describes only the harmless beginning (size and CRC
        # match), the data contains more. The scanner must not see only the beginning.
        full, prefix = b"// clean\nmalicious();\n", b"// clean\n"
        crc = zlib.crc32(prefix)
        for method in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", method) as zf:
                zf.writestr("a.js", full)
            data = buf.getvalue()
            with self.subTest(method=method, where="central"):
                self.assert_rejected(patch(data, "a.js", central_crc=crc, central_usize=len(prefix),
                                           central_csize=len(prefix) if method == zipfile.ZIP_STORED else None))
            with self.subTest(method=method, where="central+local"):
                both = patch(data, "a.js", central_crc=crc, central_usize=len(prefix), local_crc=crc,
                             local_usize=len(prefix))
                if method == zipfile.ZIP_STORED:
                    both = patch(both, "a.js", central_csize=len(prefix), local_csize=len(prefix))
                self.assert_rejected(both)

    def test_layout_must_be_unambiguous(self):
        base = build([("a.js", "x"), ("b.js", "y")])
        self.assert_rejected(b"junk" + base)                      # data before the first entry
        self.assert_rejected(base + b"junk")                      # data after the directory
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("a.js", "x")
            zf.comment = b"kommentar"
        self.assert_rejected(buf.getvalue())
        # Hidden local entry between two entries that the directory does not list
        hidden = build([("a.js", "x"), ("h.js", "evil()"), ("b.js", "y")])
        self.assert_rejected(drop_central(hidden, "h.js"))
        self.assert_rejected(patch(base, "a.js", method=zipfile.ZIP_DEFLATED, only="local"))

    def test_data_descriptors_are_accepted_when_consistent(self):
        # Many store packages write size and CRC into a data descriptor after the data
        raw = io.BytesIO()
        with zipfile.ZipFile(Unseekable(raw), "w", zipfile.ZIP_DEFLATED) as zf:
            for name, data in GOOD.items():
                zf.writestr(name, data)
        data = raw.getvalue()
        self.assertTrue(all(i.flag_bits & 0x8 for i in zipfile.ZipFile(io.BytesIO(data)).infolist()))
        self.extract(data, "demo")
        self.assert_untouched(created=True)
        self.assertEqual((self.work / "target" / "frontend" / "index.css").read_text(), "a{}\n")

    def test_data_descriptor_must_match_directory(self):
        raw = io.BytesIO()
        with zipfile.ZipFile(Unseekable(raw), "w") as zf:
            zf.writestr("a.js", "// clean\nmalicious();\n")
        data = bytearray(raw.getvalue())
        pos = data.find(b"PK\x07\x08")
        struct.pack_into("<I", data, pos + 4, 0)  # CRC in the descriptor
        self.assert_rejected(bytes(data))

    def test_manifest(self):
        def pkg(manifest=None, drop=()):
            files = dict(GOOD)
            if manifest is not None:
                files["manifest.json"] = manifest if isinstance(manifest, str) else json.dumps(manifest)
            return build([(n, d) for n, d in files.items() if n not in drop])
        self.assert_rejected(pkg(drop=("manifest.json",)), "demo")
        self.assert_rejected(pkg("{broken"), "demo")
        self.assert_rejected(pkg(dict(MANIFEST, id="other-id")), "demo")
        self.assert_rejected(pkg(drop=("backend/index.js",)), "demo")
        for bad in ("../x.js", "/etc/passwd", "frontend", None, 3):
            with self.subTest(entrypoint=bad):
                m = json.loads(json.dumps(MANIFEST))
                m["plugins"][0]["entrypoint"] = bad
                self.assert_rejected(pkg(m), "demo")
        m = {"id": "demo", "plugins": [{"kind": "workflow", "id": "w", "definition": "w/definition.json"},
                                       {"kind": "backend", "id": "b", "entrypoint": "b.js", "assets": "b/assets"}]}
        self.extract(build([("manifest.json", json.dumps(m)), ("w/definition.json", "{}"), ("b.js", ""),
                            ("b/assets/x.hbs", "")]), "demo")
        self.assert_untouched(created=True)

    def test_without_expected_id_manifest_is_not_required(self):
        # Repos from extra-repos.txt have no store entry
        self.extract(build([("a.js", "x")]))
        self.assert_untouched(created=True)

    def test_existing_target_is_not_overwritten(self):
        (self.work / "target").mkdir()
        with self.assertRaises(pp.PackageError):
            self.extract(build([("a.js", "x")]))


class SignatureTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        self.zip = self.d / "pkg.zip"
        self.zip.write_bytes(build(list(GOOD.items())))
        self.key, self.pub = self.keypair("a")
        self.sig = self.d / "pkg.zip.sig"
        self.sign(self.key, self.zip, self.sig)

    def tearDown(self):
        self.tmp.cleanup()

    def keypair(self, name):
        key = self.d / f"{name}.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(key)], check=True)
        der = subprocess.run(["openssl", "pkey", "-in", str(key), "-pubout", "-outform", "DER"],
                             check=True, capture_output=True).stdout
        return key, base64.b64encode(der).decode()

    def sign(self, key, data_file, out):
        subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", str(key), "-rawin", "-in", str(data_file),
                        "-out", str(out)], check=True)

    def test_valid_signature(self):
        pp.verify(self.zip, self.sig, self.pub)

    def test_tampered_zip_wrong_key_and_bad_inputs(self):
        tampered = self.d / "tampered.zip"
        data = bytearray(self.zip.read_bytes())
        data[len(data) // 2] ^= 1
        tampered.write_bytes(bytes(data))
        with self.assertRaises(pp.PackageError):
            pp.verify(tampered, self.sig, self.pub)
        _, other = self.keypair("b")
        with self.assertRaises(pp.PackageError):
            pp.verify(self.zip, self.sig, other)
        rsa = subprocess.run(["openssl", "genpkey", "-algorithm", "rsa", "-pkeyopt", "rsa_keygen_bits:1024"],
                             check=True, capture_output=True).stdout
        rsa_der = subprocess.run(["openssl", "pkey", "-pubout", "-outform", "DER"], input=rsa,
                                 check=True, capture_output=True).stdout
        for key in ("", "!!!", base64.b64encode(rsa_der).decode(), self.pub[:-4]):
            with self.subTest(key=key[:20]), self.assertRaises(pp.PackageError):
                pp.verify(self.zip, self.sig, key)
        with self.assertRaises(pp.PackageError):
            pp.verify(self.zip, self.d / "missing.sig", self.pub)
        short = self.d / "short.sig"
        short.write_bytes(self.sig.read_bytes()[:63])
        with self.assertRaises(pp.PackageError):
            pp.verify(self.zip, short, self.pub)


if __name__ == "__main__":
    unittest.main()
