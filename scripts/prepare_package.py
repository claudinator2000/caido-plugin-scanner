#!/usr/bin/env python3
"""Accepts a plugin package (plugin_package.zip) under control.

Usage:
  prepare_package.py verify  <zip> <sig> <public_key_base64>
  prepare_package.py extract <zip> <target-dir> [<expected-plugin-id>]

verify: checks the Ed25519 signature of the Caido store (plugin_package.zip.sig, 64 bytes)
over exactly the downloaded ZIP bytes with the public_key from the store entry (Base64,
DER/SubjectPublicKeyInfo), using the runner's OpenSSL.

extract: checks all entries of the ZIP central directory first and writes only afterwards.
Rejected are:
- paths with NUL, backslash, drive letter, absolute path, "."/".."/empty segments, too
  long or too deep;
- duplicate targets, also after Unicode normalization and case folding, and file/directory
  collisions ("a" and "a/b.js");
- anything other than regular files and directories (symlinks, devices, FIFOs, sockets);
- encrypted entries and compression methods other than stored/deflate;
- exceeding the limits in LIMITS (download, entries, single and total size, compression
  ratio), counted on the bytes actually read.
The ZIP must have an unambiguous layout so that every extractor (including Caido) sees the
same content as the scanner:
- the entries are contiguous from byte 0, the central directory follows directly, then the
  end of central directory without comment and without Zip64; nothing before, between or after;
- local header and central directory agree on name, flags, method, CRC and sizes (with a
  data descriptor: the descriptor after the data);
- the data is decompressed here: stored must have exactly the declared size, deflate must
  end exactly at the end of the compressed data and produce exactly the declared size, and
  the CRC must match. zipfile alone reads only as many bytes as the directory declares and
  would accept a truncated entry with a matching CRC.
Output goes to a new directory next to the target, without links, with exclusively created
files and fixed modes (0644/0755); only after complete success is it renamed to the target
in one step.

With an expected plugin ID (store plugins), manifest.json must be in the package, be valid
JSON, carry the same id, and every entrypoint/style of the plugins must be a file in the
package.

Every violation is an integrity error: exit 1, no target directory, the scan job fails. It
cannot be accepted through the baseline.
"""
import base64, binascii, json, os, re, stat, struct, subprocess, sys, tempfile, unicodedata, zipfile, zlib
from pathlib import Path

MiB = 1024 * 1024
# Store inventory 11/2026 (83 packages): largest ZIP 5.4 MB, 139 entries, largest file
# 4.2 MB, compression ratio at most 8.2, paths up to 59 characters and depth 3
LIMITS = {
    "zip_bytes": 50 * MiB,
    "entries": 2000,
    "file_bytes": 50 * MiB,
    "total_bytes": 200 * MiB,
    "ratio": 200,             # only for files of at least ratio_min_bytes
    "ratio_min_bytes": 64 * 1024,
    "path_length": 255,
    "depth": 20,
}
ALLOWED_METHODS = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
# SubjectPublicKeyInfo prefix of an Ed25519 key (RFC 8410), followed by the 32-byte key
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
SIGNATURE_BYTES = 64
CHUNK = 64 * 1024


class PackageError(Exception):
    pass


def shown(text):
    """Untrusted text for log output, as a JSON string without control characters."""
    return json.dumps(str(text), ensure_ascii=True)


def public_key_der(b64):
    try:
        der = base64.b64decode(b64 or "", validate=True)
    except (binascii.Error, ValueError):
        raise PackageError("public_key is not valid Base64")
    if len(der) != len(ED25519_SPKI_PREFIX) + 32 or not der.startswith(ED25519_SPKI_PREFIX):
        raise PackageError("public_key is not an Ed25519 key (DER/SubjectPublicKeyInfo)")
    return der


def verify(zip_path, sig_path, public_key_b64):
    der = public_key_der(public_key_b64)
    try:
        sig = Path(sig_path).read_bytes()
    except OSError:
        raise PackageError("signature plugin_package.zip.sig missing")
    if len(sig) != SIGNATURE_BYTES:
        raise PackageError(f"signature has {len(sig)} instead of {SIGNATURE_BYTES} bytes")
    with tempfile.TemporaryDirectory() as d:
        key = Path(d) / "key.der"
        key.write_bytes(der)
        proc = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-keyform", "DER", "-inkey", str(key),
                               "-rawin", "-in", str(zip_path), "-sigfile", str(sig_path)],
                              capture_output=True, text=True)
    if proc.returncode != 0:
        raise PackageError("invalid signature: the ZIP was not signed with the key from the store entry")


def entry_kind(info):
    """'dir', 'file' or the reason for rejection."""
    if info.create_system == 3:  # Unix: the file type is in the upper 16 bits
        fmt = stat.S_IFMT(info.external_attr >> 16)
        if fmt == stat.S_IFDIR:
            return "dir"
        if fmt not in (0, stat.S_IFREG):
            return f"not a regular object (mode {fmt:o})"
    return "dir" if info.filename.endswith("/") else "file"


def check_name(raw, limits):
    if "\x00" in raw:
        return "NUL byte in path"
    if "\\" in raw:
        return "backslash in path"
    if raw.startswith("/") or re.match(r"^[A-Za-z]:", raw):
        return "absolute path"
    name = raw[:-1] if raw.endswith("/") else raw
    segments = name.split("/")
    if any(s in ("", ".", "..") for s in segments):
        return "empty, '.' or '..' segment"
    if len(raw) > limits["path_length"] or len(segments) > limits["depth"]:
        return "path too long or too deep"
    return None


def preflight(zf, limits):
    """Checks all entries before the first write. Returns [(info, name, kind)]."""
    infos = zf.infolist()
    if len(infos) > limits["entries"]:
        raise PackageError(f"{len(infos)} entries, at most {limits['entries']} allowed")
    entries, seen, total = [], {}, 0
    for info in infos:
        raw = info.orig_filename  # Python cuts filename at the NUL byte, orig_filename does not
        problem = check_name(raw, limits)
        kind = entry_kind(info)
        if problem is None and kind not in ("dir", "file"):
            problem = kind
        if problem is None and kind == "dir" and not raw.endswith("/"):
            problem = "directory without a trailing slash"
        if problem is None and info.flag_bits & 0x1:
            problem = "encrypted"
        if problem is None and info.compress_type not in ALLOWED_METHODS:
            problem = f"compression method {info.compress_type} not allowed"
        if problem is None and kind == "file":
            if info.file_size > limits["file_bytes"]:
                problem = f"file larger than {limits['file_bytes']} bytes"
            elif (info.file_size >= limits["ratio_min_bytes"]
                  and info.file_size > limits["ratio"] * max(info.compress_size, 1)):
                problem = "compression ratio too high"
        if problem:
            raise PackageError(f"{shown(raw)}: {problem}")
        name = raw.rstrip("/")
        folded = unicodedata.normalize("NFC", name).casefold()
        if folded in seen:
            raise PackageError(f"{shown(raw)}: target occurs more than once (also after normalization)")
        seen[folded] = kind
        total += info.file_size if kind == "file" else 0
        entries.append((info, name, kind))
    if total > limits["total_bytes"]:
        raise PackageError(f"extracts to {total} bytes, at most {limits['total_bytes']} allowed")
    # A file must not also be the parent directory of another entry
    for folded, kind in seen.items():
        parts = folded.split("/")
        for i in range(1, len(parts)):
            if seen.get("/".join(parts[:i])) == "file":
                raise PackageError(f"{shown(folded)}: lies below a file of the same name")
    return entries


LOCAL_HEADER = struct.Struct("<IHHHHHIIIHH")  # signature, version, flags, method, time, date, CRC, sizes, lengths
EOCD = struct.Struct("<IHHHHIIH")
DESCRIPTOR_SIG = b"PK\x07\x08"


def check_layout(data, zf, entries):
    """Checks that local headers, data and central directory fit together unambiguously.
    Returns the start of each entry's compressed data."""
    # End of central directory: exactly at the end of the file, without comment, without Zip64
    if len(data) < EOCD.size:
        raise PackageError("no ZIP end of central directory")
    sig, disk, cd_disk, n_disk, n_total, cd_size, cd_offset, comment_len = EOCD.unpack_from(data, len(data) - EOCD.size)
    if sig != 0x06054B50 or comment_len or disk or cd_disk or n_disk != n_total:
        raise PackageError("end of central directory missing, has a comment or several parts")
    if 0xFFFF in (n_disk, n_total) or 0xFFFFFFFF in (cd_size, cd_offset) or data.find(b"PK\x06\x06") >= 0:
        raise PackageError("Zip64 is not accepted")
    if n_total != len(entries) or cd_offset + cd_size != len(data) - EOCD.size:
        raise PackageError("central directory not directly before its end, or count mismatch")
    starts, pos = [], 0
    for info, name, kind in sorted(entries, key=lambda e: e[0].header_offset):
        if info.header_offset != pos:
            raise PackageError(f"{shown(info.orig_filename)}: gap or overlap before the entry")
        if pos + LOCAL_HEADER.size > len(data):
            raise PackageError("local header truncated")
        (sig, _, flags, method, _, _, crc, csize, usize, nlen, xlen) = LOCAL_HEADER.unpack_from(data, pos)
        raw_name = data[pos + LOCAL_HEADER.size:pos + LOCAL_HEADER.size + nlen]
        central_name = info.orig_filename.encode("utf-8" if info.flag_bits & 0x800 else "cp437")
        if sig != 0x04034B50 or raw_name != central_name:
            raise PackageError(f"{shown(info.orig_filename)}: local header does not match the central directory")
        if flags != info.flag_bits or method != info.compress_type:
            raise PackageError(f"{shown(info.orig_filename)}: flags or method differ from the central directory")
        if 0xFFFFFFFF in (csize, usize, info.compress_size, info.file_size):
            raise PackageError("Zip64 is not accepted")
        start = pos + LOCAL_HEADER.size + nlen + xlen
        end = start + info.compress_size
        if end > cd_offset:
            raise PackageError(f"{shown(info.orig_filename)}: data reaches into the central directory")
        expected = (info.CRC, info.compress_size, info.file_size)
        if flags & 0x8:
            # Data descriptor after the data, with or without signature; check both readings
            for length, fields_at in ((16, end + 4), (12, end)):
                if length == 16 and data[end:end + 4] != DESCRIPTOR_SIG:
                    continue
                if fields_at + 12 <= len(data) and struct.unpack_from("<III", data, fields_at) == expected:
                    end += length
                    break
            else:
                raise PackageError(f"{shown(info.orig_filename)}: data descriptor does not match the central directory")
        elif (crc, csize, usize) != expected:
            raise PackageError(f"{shown(info.orig_filename)}: CRC or size in the local header differ")
        starts.append((info, name, kind, start))
        pos = end
    if pos != cd_offset:
        raise PackageError("data between the last entry and the central directory")
    return starts


def entry_bytes(data, info, start):
    """Decompresses an entry's data in blocks and checks size, end of stream and CRC."""
    raw = memoryview(data)[start:start + info.compress_size]
    if info.compress_type == zipfile.ZIP_STORED:
        if info.compress_size != info.file_size:
            raise PackageError(f"{shown(info.orig_filename)}: stored, but sizes differ")
        for i in range(0, len(raw), CHUNK):
            yield bytes(raw[i:i + CHUNK])
        return
    d = zlib.decompressobj(-15)
    for i in range(0, len(raw), CHUNK):
        pending = bytes(raw[i:i + CHUNK])
        while True:
            # Output limited to CHUNK; unprocessed input is in unconsumed_tail, held-back
            # output is fetched by another call with empty input
            out = d.decompress(pending, CHUNK)
            pending = d.unconsumed_tail
            if out:
                yield out
            if d.eof or (not pending and not out):
                break
        if d.eof:
            if d.unused_data or pending or i + CHUNK < len(raw):
                raise PackageError(f"{shown(info.orig_filename)}: data after the end of the deflate stream")
            return
    raise PackageError(f"{shown(info.orig_filename)}: deflate stream does not end with the data")


def write_entries(data, entries, root, limits):
    total = 0
    for info, name, kind, start in entries:
        path = root.joinpath(*name.split("/"))
        if kind == "dir":
            if info.file_size or any(entry_bytes(data, info, start)):
                raise PackageError(f"{shown(name)}: directory with content")
            path.mkdir(mode=0o755, parents=True, exist_ok=True)
            continue
        path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        written, crc = 0, 0
        with os.fdopen(fd, "wb") as out:
            for chunk in entry_bytes(data, info, start):
                written += len(chunk)
                total += len(chunk)
                # The sizes in the central directory are the package's claims: count actual bytes
                if written > info.file_size or written > limits["file_bytes"] or total > limits["total_bytes"]:
                    raise PackageError(f"{shown(name)}: more data than declared or allowed")
                crc = zlib.crc32(chunk, crc)
                out.write(chunk)
        if written != info.file_size or crc != info.CRC:
            raise PackageError(f"{shown(name)}: size or CRC differs from the central directory")


def check_manifest(root, expected_id):
    path = root / "manifest.json"
    if not path.is_file() or path.is_symlink():
        raise PackageError("manifest.json missing from the package")
    try:
        manifest = json.loads(path.read_bytes())
    except (ValueError, UnicodeDecodeError):
        raise PackageError("manifest.json is not valid JSON")
    if not isinstance(manifest, dict) or manifest.get("id") != expected_id:
        got = manifest.get("id") if isinstance(manifest, dict) else None
        raise PackageError(f"manifest.json: id {shown(got)} instead of {shown(expected_id)} from the store")
    plugins = manifest.get("plugins")
    if not isinstance(plugins, list):
        raise PackageError("manifest.json: plugins is not a list")
    for p in plugins:
        if not isinstance(p, dict) or not ({"entrypoint", "definition"} & set(p)):
            raise PackageError("manifest.json: plugin without entrypoint or definition")
        # Store inventory 11/2026: frontend/backend with entrypoint (and style, assets),
        # workflow with definition; assets is a directory
        for field, want_dir in (("entrypoint", False), ("style", False), ("definition", False), ("assets", True)):
            if field not in p:
                continue
            ref = p[field]
            ok = isinstance(ref, str) and not check_name(ref, LIMITS) and not ref.endswith("/")
            if ok:
                target = root / ref
                ok = target.is_dir() if want_dir else target.is_file()
            if not ok:
                what = "not a directory" if want_dir else "not a file"
                raise PackageError(f"manifest.json: {field} {shown(ref)} is {what} in the package")


def extract(zip_path, dest, expected_id=None, limits=LIMITS):
    zip_path, dest = Path(zip_path), Path(dest)
    if zip_path.stat().st_size > limits["zip_bytes"]:
        raise PackageError(f"ZIP larger than {limits['zip_bytes']} bytes")
    if dest.exists():
        raise PackageError(f"{dest} already exists")
    tmp = Path(tempfile.mkdtemp(prefix=f".{dest.name}-", dir=dest.parent))
    try:
        try:
            data = zip_path.read_bytes()
            with zipfile.ZipFile(zip_path) as zf:
                entries = check_layout(data, zf, preflight(zf, limits))
            write_entries(data, entries, tmp, limits)
        except (zipfile.BadZipFile, zipfile.LargeZipFile, NotImplementedError, EOFError, zlib.error) as e:
            raise PackageError(f"ZIP corrupt or inconsistent: {shown(e)}")
        if expected_id is not None:
            check_manifest(tmp, expected_id)
        os.rename(tmp, dest)
    except BaseException:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    return len(entries)


def main(argv):
    try:
        if len(argv) == 4 and argv[0] == "verify":
            verify(*argv[1:])
            print("Signature valid (key from the store entry)")
        elif len(argv) in (3, 4) and argv[0] == "extract":
            n = extract(argv[1], argv[2], argv[3] if len(argv) == 4 else None)
            print(f"{n} entries checked and extracted")
        else:
            print(__doc__, file=sys.stderr)
            return 2
    except PackageError as e:
        print(f"ERROR (integrity): {e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
