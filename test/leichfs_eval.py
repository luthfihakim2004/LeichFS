#!/usr/bin/env python3
"""leichfs_eval.py - evaluation toolkit for LeichFS (AES-256-GCM FUSE filesystem).

Thesis: "Desain dan Evaluasi Sistem Berkas Ruang Pengguna Terenkripsi dengan
AES-256-GCM serta Derivasi Kunci Argon2id-HKDF".

Subcommands (offline = reads backing/ciphertext files only):
  format      offline  Validate header + record layout + nonce structure.
  randomness  offline  Entropy, chi-square, monobit, serial correlation of ciphertext.
  compare     offline  Bit-difference / salt / nonce comparison of two files.
  overhead    offline  Predicted vs actual on-disk size (+ stat() consistency on mount).
  security    online   Round-trip, fuzz vs model, nonce freshness, tamper detection.
  bench       online   Throughput/latency vs. a baseline directory (mean, sd, 95% CI).
  verify      offline  Independent reference decryptor: unwrap master key from .leichfs.conf,
                       re-derive file keys (HKDF), authenticate+decrypt every chunk, and
                       optionally compare against the mounted filesystem's output.
  kdf         local    Argon2id (optional argon2-cffi) and HKDF-SHA256 timing.

"online" commands need a mounted LeichFS: --mount (plaintext view) and --backing
(ciphertext directory).  Requires Python >= 3.10.  Stdlib only; `verify` and the Argon2id sweep need
`pip install argon2-cffi cryptography`.

Caveat for the paper: statistical tests on AES-GCM ciphertext only check that the
keystream looks random; they are sanity checks, not proofs of security.
"""

import argparse
import csv
import errno
import getpass
import hashlib
import hmac
import json
import math
import os
import random
import shutil
import statistics
import struct
import sys
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

# ---- From enc/params.hpp / DESIGN.md ------------------------------------
HEADER_SIZE = 64
MAGIC = b"LEICHFSX"
ENC_VERSION = 1
CHUNK_SIZE = 64 * 1024
NONCE_SIZE = 12
TAG_SIZE = 16
CONF_NAME = ".leichfs.conf"
KEY_SIZE = 32
INFO_KEY = b"leichfs-file-key"
INFO_NONCE = b"leichfs-nonce-base"
REC_SIZE = NONCE_SIZE + CHUNK_SIZE + TAG_SIZE  # 65564

REPORT: dict = {"checks": [], "metrics": {}}
DROP_CACHES = False
BACKING_MAP = None  # (mount_root, backing_root): also evict ciphertext pages when dropping caches
DIAG_MASTER = None  # master key (if --conf given) for spec-authentication diagnostics


class FormatError(ValueError):
    pass


# ---- Reporting helpers --------------------------------------------------
def check(group: str, name: str, ok, detail: str = "") -> bool | None:
    tag = {True: "PASS", False: "FAIL", None: "INFO"}[ok]
    print(f"  [{tag}] {name}" + (f" - {detail}" if detail else ""))
    REPORT["checks"].append({"group": group, "name": name, "result": tag, "detail": detail})
    return ok


T95 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365, 8: 2.306,
       9: 2.262, 10: 2.228, 11: 2.201, 12: 2.179, 13: 2.160, 14: 2.145, 15: 2.131,
       16: 2.120, 17: 2.110, 18: 2.101, 19: 2.093, 20: 2.086, 25: 2.060, 30: 2.042}


def tcrit(df: int) -> float:
    for k in sorted(T95):
        if df <= k:
            return T95[k]  # conservative: next-higher df
    return 1.96


def summarize(values: list[float]) -> dict:
    n = len(values)
    mean = statistics.fmean(values)
    sd = statistics.stdev(values) if n > 1 else 0.0
    ci = tcrit(n - 1) * sd / math.sqrt(n) if n > 1 else 0.0
    return {"n": n, "mean": mean, "sd": sd, "median": statistics.median(values),
            "ci95": ci, "min": min(values), "max": max(values)}


# ---- Format parsing -----------------------------------------------------
@dataclass(frozen=True)
class Header:
    version: int
    chunk_size: int
    salt: bytes
    reserved: bytes
    plain_length: int

    @property
    def n_chunks(self) -> int:
        return -(-self.plain_length // self.chunk_size)

    def expected_data_len(self) -> int:
        full, tail = divmod(self.plain_length, self.chunk_size)
        total = full * (NONCE_SIZE + self.chunk_size + TAG_SIZE)
        return total + (NONCE_SIZE + tail + TAG_SIZE if tail else 0)

    def aad(self, idx: int) -> bytes:
        """AAD[40] = magic || be32(version) || be32(chunk_sz) || salt || be64(idx)."""
        return (MAGIC + struct.pack(">II", self.version, self.chunk_size)
                + self.salt + struct.pack(">Q", idx))


@dataclass(frozen=True)
class Record:
    index: int
    nonce: bytes
    ciphertext: bytes
    tag: bytes


def read_header(path) -> Header:
    with open(path, "rb") as f:
        raw = f.read(HEADER_SIZE)
    if len(raw) != HEADER_SIZE:
        raise FormatError("file shorter than 64-byte header")
    if raw[:8] != MAGIC:
        raise FormatError(f"bad magic {raw[:8]!r}")
    version, chunk = struct.unpack("<II", raw[8:16])
    if chunk == 0 or chunk > (8 << 20):
        raise FormatError(f"implausible chunk size {chunk}")
    plain = struct.unpack(">Q", raw[56:64])[0]
    return Header(version, chunk, raw[16:32], raw[32:56], plain)


def iter_records(path, hdr: Header):
    expected = hdr.expected_data_len()
    actual = os.path.getsize(path) - HEADER_SIZE
    if actual != expected:
        raise FormatError(f"data length mismatch: expected {expected}, got {actual}")
    with open(path, "rb") as f:
        f.seek(HEADER_SIZE)
        remaining, idx = hdr.plain_length, 0
        while remaining:
            n = min(hdr.chunk_size, remaining)
            rec = f.read(NONCE_SIZE + n + TAG_SIZE)
            if len(rec) != NONCE_SIZE + n + TAG_SIZE:
                raise FormatError(f"truncated record {idx}")
            yield Record(idx, rec[:NONCE_SIZE], rec[NONCE_SIZE:NONCE_SIZE + n],
                         rec[NONCE_SIZE + n:])
            remaining -= n
            idx += 1


def collect_files(paths) -> list[Path]:
    out = []
    for p in map(Path, paths):
        if p.is_dir():
            out += [q for q in sorted(p.rglob("*")) if q.is_file() and q.name != CONF_NAME]
        else:
            out.append(p)
    return out


def predicted_size(plain_len: int, chunk: int = CHUNK_SIZE) -> int:
    n = -(-plain_len // chunk)
    return HEADER_SIZE + n * (NONCE_SIZE + TAG_SIZE) + plain_len


# ---- Statistics ---------------------------------------------------------
def shannon(counts) -> float:
    n = sum(counts)
    return -sum((c / n) * math.log2(c / n) for c in counts if c) if n else 0.0


def _gammaincc(a: float, x: float) -> float:
    """Regularised upper incomplete gamma Q(a, x)."""
    if x <= 0:
        return 1.0
    lg = -x + a * math.log(x) - math.lgamma(a)
    if x < a + 1:
        term = s = 1.0 / a
        n = a
        for _ in range(2000):
            n += 1
            term *= x / n
            s += term
            if abs(term) < abs(s) * 1e-15:
                break
        return 1.0 - s * math.exp(lg)
    tiny = 1e-300
    b = x + 1 - a
    c, d = 1 / tiny, 1 / b
    h = d
    for i in range(1, 2000):
        an = -i * (i - a)
        b += 2
        d = an * d + b
        d = tiny if abs(d) < tiny else d
        c = b + an / c
        c = tiny if abs(c) < tiny else c
        d = 1 / d
        delta = d * c
        h *= delta
        if abs(delta - 1) < 1e-15:
            break
    return math.exp(lg) * h


def chi2_p(counts) -> tuple[float, float]:
    n = sum(counts)
    exp = n / 256
    chi2 = sum((c - exp) ** 2 / exp for c in counts)
    return chi2, _gammaincc(255 / 2, chi2 / 2)


def monobit_p(ones: int, nbits: int) -> float:
    s = abs(2 * ones - nbits) / math.sqrt(nbits)
    return math.erfc(s / math.sqrt(2))


def serial_corr(data: bytes) -> float:
    n = len(data)
    if n < 2:
        return float("nan")
    s, s2 = sum(data), sum(b * b for b in data)
    s12 = sum(a * b for a, b in zip(data, data[1:])) + data[-1] * data[0]
    den = n * s2 - s * s
    return (n * s12 - s * s) / den if den else float("nan")


def bit_diff(a: bytes, b: bytes) -> float | None:
    n = min(len(a), len(b))
    if n == 0:
        return None
    x = int.from_bytes(a[:n], "big") ^ int.from_bytes(b[:n], "big")
    return x.bit_count() * 100.0 / (n * 8)


class StreamStats:
    """Accumulates byte statistics over ciphertext bytes."""

    def __init__(self, sample_cap=4 << 20):
        self.counts = [0] * 256
        self.ones = 0
        self.n = 0
        self.sample = bytearray()
        self.cap = sample_cap

    def add(self, data: bytes):
        for byte, c in Counter(data).items():
            self.counts[byte] += c
        self.ones += int.from_bytes(data, "big").bit_count() if data else 0
        self.n += len(data)
        if len(self.sample) < self.cap:
            self.sample += data[: self.cap - len(self.sample)]

    def result(self) -> dict:
        if self.n == 0:
            return {"bytes": 0}
        chi2, p = chi2_p(self.counts)
        return {"bytes": self.n, "entropy": shannon(self.counts), "chi2": chi2,
                "chi2_p": p, "monobit_p": monobit_p(self.ones, self.n * 8),
                "serial_corr": serial_corr(bytes(self.sample)),
                "mean_byte": sum(i * c for i, c in enumerate(self.counts)) / self.n}


def stats_ok(r: dict, alpha=0.001) -> bool:
    return r["chi2_p"] >= alpha and r["monobit_p"] >= alpha


# ---- Subcommand: format -------------------------------------------------
def cmd_format(args) -> int:
    fails = 0
    for path in collect_files(args.paths):
        print(f"\n[+] {path}")
        try:
            hdr = read_header(path)
        except FormatError as e:
            check("format", "header parses", False, str(e))
            fails += 1
            continue
        g = "format"
        r = [
            check(g, "version == 1", hdr.version == ENC_VERSION, f"version={hdr.version}"),
            check(g, "chunk_sz == 65536", hdr.chunk_size == CHUNK_SIZE, str(hdr.chunk_size)),
            check(g, "reserved[24] all zero", not any(hdr.reserved)),
            check(g, "salt[16] not all-zero", any(hdr.salt), hdr.salt.hex()),
        ]
        actual = os.path.getsize(path) - HEADER_SIZE
        exp = hdr.expected_data_len()
        r.append(check(g, "on-disk size matches design formula", actual == exp,
                       f"plain={hdr.plain_length} expected_data={exp} actual={actual}"))
        try:
            prefixes, bad_ctr, zero_tags = set(), 0, 0
            n = 0
            for rec in iter_records(path, hdr):
                n += 1
                if rec.nonce[8:] != struct.pack(">I", rec.index):
                    bad_ctr += 1
                prefixes.add(rec.nonce[:8])
                zero_tags += not any(rec.tag)
            r.append(check(g, "nonce[8:12] == be32(chunk_index) for all chunks", bad_ctr == 0,
                           f"{bad_ctr} mismatches of {n}"))
            r.append(check(g, "nonce random[8] unique within file", len(prefixes) == n,
                           f"{len(prefixes)} unique of {n}"))
            r.append(check(g, "no all-zero tags", zero_tags == 0, f"{zero_tags}"))
        except FormatError as e:
            r.append(check(g, "records parse", False, str(e)))
        fails += sum(x is False for x in r)
    print(f"\nSummary: {fails} failed checks")
    return 1 if fails else 0


# ---- Subcommand: randomness ---------------------------------------------
def analyze_file_ct(path, max_bytes) -> tuple[Header, dict]:
    hdr = read_header(path)
    st = StreamStats()
    for rec in iter_records(path, hdr):
        st.add(rec.ciphertext)
        if st.n >= max_bytes:
            break
    return hdr, st.result()


def cmd_randomness(args) -> int:
    print("[+] Ciphertext randomness (chunk payload only; nonce/tag excluded)")
    print("    Note: needs >= ~10 KiB per file for chi-square to be meaningful.")
    print(f"    {'file':40} {'bytes':>9} {'H(bits/B)':>9} {'chi2 p':>8} {'mono p':>8} {'serial':>8}")
    fails, all_rows = 0, []
    for path in collect_files(args.paths):
        try:
            hdr, r = analyze_file_ct(path, args.max_bytes)
        except FormatError as e:
            print(f"    {str(path)[-40:]:40} skipped: {e}")
            continue
        if r["bytes"] < 1024:
            print(f"    {str(path)[-40:]:40} {r['bytes']:>9} (too small, skipped)")
            continue
        ok = stats_ok(r) if r["bytes"] >= 10240 else None
        fails += ok is False
        print(f"    {str(path)[-40:]:40} {r['bytes']:>9} {r['entropy']:>9.5f} "
              f"{r['chi2_p']:>8.4f} {r['monobit_p']:>8.4f} {r['serial_corr']:>8.5f}"
              f"  {'' if ok is None else ('ok' if ok else 'SUSPECT')}")
        all_rows.append({"file": str(path), **r})
    REPORT["metrics"]["randomness"] = all_rows
    print("\n    Expect per-file p-values ~U(0,1): about 0.1% of good files fall below 0.001 by chance.")
    return 1 if fails else 0


# ---- Subcommand: compare ------------------------------------------------
def cmd_compare(args) -> int:
    ha, hb = read_header(args.a), read_header(args.b)
    ra, rb = list(iter_records(args.a, ha)), list(iter_records(args.b, hb))
    print(f"[+] A: {args.a} ({ha.plain_length} B)   B: {args.b} ({hb.plain_length} B)")
    check("compare", "per-file salts differ", ha.salt != hb.salt,
          f"A={ha.salt.hex()[:16]}.. B={hb.salt.hex()[:16]}..")
    diffs = []
    for x, y in zip(ra, rb):
        d = bit_diff(x.ciphertext, y.ciphertext)
        if d is not None:
            diffs.append(d)
        if x.nonce == y.nonce:
            check("compare", f"chunk {x.index} nonce differs", False, "identical nonce")
        if x.tag == y.tag:
            check("compare", f"chunk {x.index} tag differs", False, "identical tag")
    total = bit_diff(b"".join(r.ciphertext for r in ra), b"".join(r.ciphertext for r in rb))
    if total is None:
        print("    nothing to compare")
        return 0
    print(f"    bit difference (all chunks): {total:.3f}%  (per-chunk mean {statistics.fmean(diffs):.3f}%)")
    ok = 49.0 <= total <= 51.0 if sum(len(r.ciphertext) for r in ra) >= 4096 else None
    check("compare", "bit difference within 50% +/- 1%", ok,
          "meaningful only for >= 4 KiB" if ok is None else f"{total:.3f}%")
    return 0 if ok is not False else 1


# ---- Subcommand: overhead -----------------------------------------------
def cmd_overhead(args) -> int:
    print("[+] Reference model: overhead by plaintext size")
    print(f"    {'plain':>12} {'LeichFS disk':>14} {'ovh B':>8} {'ovh %':>8} {'gocryptfs ovh %':>16}")
    for n in [0, 1, 1024, 4096, 65536, 65537, 1 << 20, 16 << 20, 1 << 30]:
        disk = predicted_size(n)
        goc_blocks = -(-n // 4096)
        goc = 18 + goc_blocks * 32 if n else 18
        pct = f"{(disk - n) * 100 / n:8.3f}" if n else "     n/a"
        gpct = f"{goc * 100 / n:16.3f}" if n else "             n/a"
        print(f"    {n:>12} {disk:>14} {disk - n:>8} {pct} {gpct}")
    print("    (gocryptfs model: 18 B header, 32 B per 4 KiB block - reference only)")
    if not args.backing:
        return 0
    print(f"\n[+] Measured on {args.backing}")
    rows, bad = [], 0
    for path in collect_files([args.backing]):
        try:
            hdr = read_header(path)
        except FormatError:
            continue
        disk = path.stat().st_size
        ok = disk == predicted_size(hdr.plain_length, hdr.chunk_size)
        row = {"file": str(path), "plain": hdr.plain_length, "disk": disk,
               "overhead": disk - hdr.plain_length, "matches_model": ok}
        if args.mount:
            rel = path.relative_to(args.backing)
            try:
                row["mount_stat_size"] = (Path(args.mount) / rel).stat().st_size
                row["stat_consistent"] = row["mount_stat_size"] == hdr.plain_length
            except OSError as e:
                row["stat_consistent"] = False
                row["mount_stat_size"] = f"err {e.errno}"
        bad += (not ok) + (row.get("stat_consistent") is False)
        rows.append(row)
    for r in rows[: args.limit]:
        print(f"    {r['plain']:>12} -> {r['disk']:>12}  +{r['overhead']:<8} "
              f"{'ok' if r['matches_model'] else 'MISMATCH'}"
              f"{'' if 'stat_consistent' not in r else ('  stat ok' if r['stat_consistent'] else '  STAT MISMATCH')}"
              f"  {Path(r['file']).name}")
    tot_p, tot_d = sum(r["plain"] for r in rows), sum(r["disk"] for r in rows)
    if rows:
        print(f"    files={len(rows)}  total plain={tot_p}  disk={tot_d}  "
              f"overall overhead={(tot_d - tot_p) * 100 / max(tot_p, 1):.4f}%")
    REPORT["metrics"]["overhead"] = rows
    check("overhead", "all files match predicted size (and stat)", bad == 0, f"{bad} mismatches")
    return 1 if bad else 0


# ---- Online helpers -----------------------------------------------------
def _fadvise_dontneed(path):
    try:
        fd = os.open(path, os.O_RDONLY)
        os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
        os.close(fd)
    except OSError:
        pass


def drop_cache(path):
    _fadvise_dontneed(path)
    if BACKING_MAP:  # evict the ciphertext file behind a mount path too
        try:
            rel = Path(path).resolve().relative_to(BACKING_MAP[0])
            _fadvise_dontneed(BACKING_MAP[1] / rel)
        except (ValueError, OSError):
            pass


def drop_system_caches():
    if DROP_CACHES and os.geteuid() == 0:
        os.sync()
        try:
            Path("/proc/sys/vm/drop_caches").write_text("3\n")
        except OSError:
            pass


def read_all(path) -> tuple[str, bytes | int]:
    """Fresh open + cache drop + read to EOF.  Returns ('ok', data) or ('err', errno)."""
    try:
        drop_cache(path)
        drop_system_caches()
        fd = os.open(path, os.O_RDONLY)
        try:
            chunks = []
            while True:
                b = os.read(fd, 1 << 20)
                if not b:
                    break
                chunks.append(b)
        finally:
            os.close(fd)
        return "ok", b"".join(chunks)
    except OSError as e:
        return "err", e.errno or -1


def pread_fresh(path, off, ln) -> tuple[str, bytes | int]:
    try:
        drop_cache(path)
        fd = os.open(path, os.O_RDONLY)
        try:
            return "ok", os.pread(fd, ln, off)
        finally:
            os.close(fd)
    except OSError as e:
        return "err", e.errno or -1


def write_file(path, data: bytes, fsync=True):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        mv, off = memoryview(data), 0
        while off < len(data):
            off += os.write(fd, mv[off:off + (1 << 20)])
        if fsync:
            os.fsync(fd)
    finally:
        os.close(fd)


# ---- Subcommand: security -----------------------------------------------
class SecEnv:
    def __init__(self, mount, backing, settle, seed):
        self.sub = "leichfs_eval_sec"
        self.pdir, self.cdir = Path(mount) / self.sub, Path(backing) / self.sub
        self.pdir.mkdir(exist_ok=True)
        self.settle = settle
        self.rng = random.Random(seed)

    def p(self, name):
        return self.pdir / name

    def c(self, name):
        return self.cdir / name

    def make(self, name, size) -> bytes:
        data = self.rng.randbytes(size)
        write_file(self.p(name), data)
        return data

    def cleanup(self):
        try:
            shutil.rmtree(self.pdir, ignore_errors=True)
        except OSError:
            pass


def off(i: int) -> int:
    return HEADER_SIZE + i * REC_SIZE


def t_roundtrip(env: SecEnv) -> int:
    print("\n[+] Round-trip, size and layout consistency")
    fails = 0
    for size in [0, 1, 15, 4095, 65535, 65536, 65537, 3 * CHUNK_SIZE + 1000, 1 << 20]:
        name = f"rt_{size}"
        data = env.make(name, size)
        st, back = read_all(env.p(name))
        ok_data = st == "ok" and hashlib.sha256(back).digest() == hashlib.sha256(data).digest()
        try:
            hdr = read_header(env.c(name))
            ok_layout = (hdr.plain_length == size
                         and env.c(name).stat().st_size == predicted_size(size)
                         and env.p(name).stat().st_size == size)
            detail = f"disk={env.c(name).stat().st_size} predicted={predicted_size(size)}"
        except (FormatError, OSError) as e:
            ok_layout, detail = False, str(e)
        r = check("roundtrip", f"size={size}", ok_data and ok_layout,
                  detail if ok_data else f"read-back mismatch ({st}, {back if st == 'err' else ''})")
        fails += r is False
    return fails


def _pw(fd, model, o, data):
    os.pwrite(fd, data, o)
    if o > len(model):
        model.extend(bytes(o - len(model)))
    model[o:o + len(data)] = data


def _tr(fd, model, n):
    os.ftruncate(fd, n)
    if n < len(model):
        del model[n:]
    else:
        model.extend(bytes(n - len(model)))


def ename(e: OSError) -> str:
    return f"{errno.errorcode.get(e.errno, e.errno)} ({os.strerror(e.errno or 0)})"


def unwrap_master(conf: dict, pw: bytes, wrap_aad: bytes) -> bytes:
    from argon2.low_level import Type, hash_secret_raw
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    kek = hash_secret_raw(pw, conf["salt"], conf["argon2_t"], conf["argon2_m"],
                          conf["argon2_p"], KEY_SIZE, Type.ID)
    return AESGCM(kek).decrypt(conf["wrap_nonce"], conf["wrapped_key"] + conf["wrap_tag"], wrap_aad or None)


def spec_auth_failures(cpath, hdr: Header, master: bytes) -> list[int]:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    aes = AESGCM(hkdf_sha256(master, hdr.salt, INFO_KEY, KEY_SIZE))
    bad = []
    for rec in iter_records(cpath, hdr):
        try:
            aes.decrypt(rec.nonce, rec.ciphertext + rec.tag, hdr.aad(rec.index))
        except InvalidTag:
            bad.append(rec.index)
    return bad


def _dead(err_no, where):
    if err_no == errno.ENOTCONN:
        raise OSError(errno.ENOTCONN, f"FUSE daemon died during: {where}")


def diagnose_backing(cpath) -> str:
    """One-line structural diagnosis of a backing file (holes, size mismatch, bad counters)."""
    cpath = Path(cpath)
    if not cpath.exists():
        return "backing file missing"
    try:
        hdr = read_header(cpath)
    except FormatError as e:
        return f"backing header invalid: {e}"
    st = cpath.stat()
    exp = predicted_size(hdr.plain_length, hdr.chunk_size)
    parts = [f"header plain_len={hdr.plain_length}",
             f"disk={st.st_size} predicted={exp} "
             + ("(ok)" if st.st_size == exp else f"(MISMATCH {st.st_size - exp:+d} B)"),
             f"allocated={st.st_blocks * 512} B" + (" SPARSE" if st.st_blocks * 512 + 4096 < st.st_size else "")]
    zero, badctr = [], []
    stride = NONCE_SIZE + hdr.chunk_size + TAG_SIZE
    with open(cpath, "rb") as f:
        f.seek(HEADER_SIZE)
        i = 0
        while True:
            rec = f.read(stride)
            if not rec:
                break
            if not any(rec[:NONCE_SIZE]):
                zero.append(i)
            elif rec[8:NONCE_SIZE] != struct.pack(">I", i):
                badctr.append(i)
            i += 1
    if zero:
        parts.append(f"zero-nonce (hole) records at {zero[:10]}")
    if badctr:
        parts.append(f"nonce counter != index at records {badctr[:10]}")
    if DIAG_MASTER is not None:
        try:
            bad = spec_auth_failures(cpath, hdr, DIAG_MASTER)
            parts.append(f"SPEC-AUTH FAILS at chunks {bad[:10]}" if bad else
                         "all chunks authenticate under the spec (data on disk is valid; look at the FS read/length logic)")
        except FormatError as e:
            parts.append(f"spec-auth skipped: {e}")
    return "; ".join(parts)


def t_edge(env: SecEnv, only=None) -> int:
    print("\n[+] Edge cases: holes, truncate, chunk-boundary read-modify-write (each on a fresh file)")
    C, rb = CHUNK_SIZE, env.rng.randbytes
    cases = [
        ("pwrite past EOF, hole inside first chunk", 100, lambda fd, m: _pw(fd, m, 5000, rb(10))),
        ("pwrite past EOF, hole spans 2 whole chunks", 100, lambda fd, m: _pw(fd, m, 3 * C + 10, rb(10))),
        ("pwrite exactly at EOF == chunk boundary", C, lambda fd, m: _pw(fd, m, C, rb(10))),
        ("pwrite past EOF from chunk boundary + gap", C, lambda fd, m: _pw(fd, m, 2 * C + 5, rb(10))),
        ("ftruncate extend inside same chunk", 100, lambda fd, m: _tr(fd, m, 5000)),
        ("ftruncate extend across chunks", 100, lambda fd, m: _tr(fd, m, 3 * C + 7)),
        ("ftruncate extend from exact boundary by 1", C, lambda fd, m: _tr(fd, m, C + 1)),
        ("ftruncate extend from exact boundary by a chunk", C, lambda fd, m: _tr(fd, m, 2 * C)),
        ("ftruncate shrink to mid-chunk", 3 * C, lambda fd, m: _tr(fd, m, C + 100)),
        ("ftruncate shrink to chunk boundary", 3 * C, lambda fd, m: _tr(fd, m, C)),
        ("ftruncate to 0, then write 10 bytes", 2 * C, lambda fd, m: (_tr(fd, m, 0), _pw(fd, m, 0, rb(10)))),
        ("shrink then re-extend (old bytes must read as zero)", 2 * C,
         lambda fd, m: (_tr(fd, m, 100), _tr(fd, m, 2 * C))),
        ("overwrite across a chunk boundary (RMW of 2 chunks)", 2 * C, lambda fd, m: _pw(fd, m, C - 50, rb(100))),
        ("overwrite middle of last partial chunk", C + 1000, lambda fd, m: _pw(fd, m, C + 500, rb(10))),
        ("write extends file across a chunk boundary", C - 10, lambda fd, m: _pw(fd, m, C - 10, rb(100))),
        ("pwrite past EOF crossing exactly one boundary (no whole-chunk gap)", 100,
         lambda fd, m: _pw(fd, m, C + 5, rb(10))),
        ("pwrite into EMPTY file at 2C+5", 0, lambda fd, m: _pw(fd, m, 2 * C + 5, rb(10))),
        ("ftruncate extend EMPTY file across chunks (0 -> 2C+5)", 0, lambda fd, m: _tr(fd, m, 2 * C + 5)),
        ("ftruncate shrink single-chunk file (5000 -> 100)", 5000, lambda fd, m: _tr(fd, m, 100)),
        ("ftruncate shrink by one byte inside last chunk (2C -> 2C-1)", 2 * C, lambda fd, m: _tr(fd, m, 2 * C - 1)),
        ("overwrite a whole aligned chunk (full-chunk shortcut)", 2 * C, lambda fd, m: _pw(fd, m, 0, rb(C))),
        ("overwrite the entire partial last chunk exactly", C + 1000, lambda fd, m: _pw(fd, m, C, rb(1000))),
        ("overwrite partial last chunk from its start AND extend it", C + 1000, lambda fd, m: _pw(fd, m, C, rb(3000))),
        ("short write at chunk start keeps the rest (no shortcut)", C + 1000, lambda fd, m: _pw(fd, m, C, rb(10))),
        ("write spanning 2 chunks from offset 0 over a longer file", 3 * C + 500, lambda fd, m: _pw(fd, m, 0, rb(2 * C + 10))),
    ]
    fails = 0
    for i, (label, init_size, ops) in enumerate(cases):
        if only is not None and i not in only:
            continue
        name = f"edge_{i}"
        try:
            model = bytearray(env.make(name, init_size))
            fd = os.open(env.p(name), os.O_RDWR)
        except OSError as e:
            _dead(e.errno, f"setup of '{label}' (previous case probably crashed it)")
            fails += check("edge", label, False, f"setup failed: {ename(e)}") is False
            continue
        err = None
        try:
            ops(fd, model)
            os.fsync(fd)
        except OSError as e:
            _dead(e.errno, label)
            err = f"operation failed: {ename(e)}"
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
        if err is None:
            st, data = read_all(env.p(name))
            if st != "ok":
                _dead(data, label + " (read-back)")
                err = f"read-back failed: {errno.errorcode.get(data, data)}"
            elif data != bytes(model):
                d = next((k for k in range(min(len(data), len(model))) if data[k] != model[k]),
                         min(len(data), len(model)))
                err = f"content differs at byte {d} (got {len(data)} B, expected {len(model)} B)"
        fails += check("edge", label, err is None, err or "") is False
        if err is not None:
            print(f"        backing: {diagnose_backing(env.c(name))}")
    return fails


def t_fuzz(env: SecEnv, n_ops: int, seeds: int) -> int:
    print("\n[+] Random pwrite/ftruncate/pread fuzz vs in-memory model (stops at first failure per seed)")
    fails = 0
    for seed in range(seeds):
        rng = random.Random(1000 + seed)
        path = env.p(f"fuzz_{seed}")
        model, failure, desc = bytearray(), None, ""
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            for i in range(n_ops):
                r = rng.random()
                try:
                    if r < 0.55:
                        base = rng.choice([0, CHUNK_SIZE, 2 * CHUNK_SIZE, 3 * CHUNK_SIZE,
                                           rng.randrange(0, 4 * CHUNK_SIZE)])
                        o = max(0, base + rng.choice([0, 1, -1, -50, 50]))
                        ln = rng.choice([1, 7, 100, 4096, CHUNK_SIZE - 1, CHUNK_SIZE, CHUNK_SIZE + 1, 70000])
                        desc = f"pwrite off={o} len={ln} (file_len={len(model)})"
                        _pw(fd, model, o, rng.randbytes(ln))
                    elif r < 0.70:
                        new = rng.choice([0, 1, CHUNK_SIZE, CHUNK_SIZE + 5, 2 * CHUNK_SIZE - 3,
                                          rng.randrange(0, 4 * CHUNK_SIZE)])
                        desc = f"ftruncate {new} (file_len={len(model)})"
                        _tr(fd, model, new)
                    else:
                        o = rng.randrange(0, max(1, len(model) + 100))
                        ln = rng.choice([1, 4096, 70000])
                        desc = f"pread off={o} len={ln} (file_len={len(model)})"
                        if os.pread(fd, ln, o) != bytes(model[o:o + ln]):
                            failure = f"op {i}: {desc} -> read returned WRONG DATA without error"
                            break
                except OSError as e:
                    _dead(e.errno, f"fuzz seed {seed} op {i}: {desc}")
                    failure = f"op {i}: {desc} -> {ename(e)}"
                    break
            if failure is None:
                os.fsync(fd)
        finally:
            os.close(fd)
        if failure is None:
            st, final = read_all(path)
            if st != "ok":
                _dead(final, f"fuzz seed {seed} final read")
                failure = f"final read failed: {errno.errorcode.get(final, final)}"
            elif final != bytes(model):
                failure = f"final content differs from model (len {len(final)} vs {len(model)})"
        fails += check("fuzz", f"seed {seed}: {n_ops} ops match model", failure is None, failure or "") is False
        if failure is not None:
            print(f"        backing: {diagnose_backing(env.c(f'fuzz_{seed}'))}")
    return fails


def nonces_of(cpath) -> list[bytes]:
    hdr = read_header(cpath)
    return [r.nonce for r in iter_records(cpath, hdr)]


def t_nonce(env: SecEnv) -> int:
    print("\n[+] Nonce freshness / key-isolation")
    fails = 0
    data = env.make("nz_a", 2 * CHUNK_SIZE)
    n0 = nonces_of(env.c("nz_a"))[0]
    seen = {n0}
    for _ in range(5):
        fd = os.open(env.p("nz_a"), os.O_WRONLY)
        os.pwrite(fd, data[:CHUNK_SIZE], 0)  # same bytes, same offset
        os.fsync(fd)
        os.close(fd)
        seen.add(nonces_of(env.c("nz_a"))[0])
    fails += check("nonce", "re-writing identical chunk 0 gives a fresh nonce each time",
                   len(seen) == 6, f"{len(seen)} distinct of 6 (reuse under same key breaks GCM)") is False

    write_file(env.p("nz_b"), data)
    ha, hb = read_header(env.c("nz_a")), read_header(env.c("nz_b"))
    ra, rb = list(iter_records(env.c("nz_a"), ha)), list(iter_records(env.c("nz_b"), hb))
    fails += check("nonce", "same plaintext in 2 files -> different salts", ha.salt != hb.salt) is False
    d = bit_diff(ra[0].ciphertext, rb[0].ciphertext)
    fails += check("nonce", "same plaintext in 2 files -> ~50% ciphertext bit difference",
                   d is not None and 49.0 <= d <= 51.0, f"{d:.3f}%") is False

    env.make("nz_zero", 0)
    write_file(env.p("nz_zero"), bytes(1 << 20))
    hz = read_header(env.c("nz_zero"))
    st = StreamStats()
    for rec in iter_records(env.c("nz_zero"), hz):
        st.add(rec.ciphertext)
    r = st.result()
    fails += check("nonce", "1 MiB of zero plaintext -> random-looking ciphertext", stats_ok(r),
                   f"H={r['entropy']:.5f} chi2_p={r['chi2_p']:.4f} mono_p={r['monobit_p']:.4f}") is False
    return fails


def tamper_cases(C=CHUNK_SIZE):
    def flip(pos):
        def f(b, _other):
            b[pos] ^= 0x01
        return f

    def swap(b, _o):
        a, c = off(0), off(1)
        b[a:a + REC_SIZE], b[c:c + REC_SIZE] = b[c:c + REC_SIZE], b[a:a + REC_SIZE]

    def replay(b, _o):
        b[off(2):off(2) + REC_SIZE] = b[off(0):off(0) + REC_SIZE]

    def zero(b, _o):
        b[off(1):off(1) + REC_SIZE] = bytes(REC_SIZE)

    def cut(n):
        def f(b, _o):
            del b[-n:]
        return f

    def drop_last(b, _o):
        del b[off(3):]

    def patch_len(delta, drop=False):
        def f(b, _o):
            if drop:
                del b[off(3):]
                new = 3 * C
            else:
                new = struct.unpack(">Q", b[56:64])[0] + delta
            b[56:64] = struct.pack(">Q", new)
        return f

    def append(b, _o):
        b.extend(os.urandom(37))

    def transplant(b, other):
        b[off(1):off(1) + REC_SIZE] = other[off(1):off(1) + REC_SIZE]

    # (name, expectation, target chunk (None=whole file), mutator)
    return [
        ("bit-flip ciphertext, chunk 1", "detect", 1, flip(off(1) + NONCE_SIZE + 100)),
        ("bit-flip auth tag, chunk 1", "detect", 1, flip(off(1) + NONCE_SIZE + C + 3)),
        ("bit-flip nonce random part, chunk 1", "detect", 1, flip(off(1) + 2)),
        ("bit-flip nonce counter part, chunk 1", "detect", 1, flip(off(1) + 11)),
        ("bit-flip ciphertext, last partial chunk", "detect", 3, flip(off(3) + NONCE_SIZE + 10)),
        ("swap chunk 0 <-> chunk 1 (reorder)", "detect", 0, swap),
        ("replay chunk 0 over chunk 2", "detect", 2, replay),
        ("zero-fill chunk 1 record", "detect", 1, zero),
        ("transplant chunk 1 from another file", "detect", 1, transplant),
        ("header: flip magic", "detect", None, flip(0)),
        ("header: flip version", "detect", None, flip(8)),
        ("header: flip chunk_sz", "detect", None, flip(12)),
        ("header: flip salt bit", "detect", None, flip(20)),
        ("header: plain_len +1", "detect", None, patch_len(+1)),
        ("header: plain_len -1", "detect", None, patch_len(-1)),
        ("truncate: cut 5 bytes off tail record", "detect", 3, cut(5)),
        ("truncate: drop last chunk, header unchanged", "detect", 3, drop_last),
        ("truncate: drop last chunk AND patch plain_len", "limit", None, patch_len(0, drop=True)),
        ("append 37 trailing garbage bytes", "limit", None, append),
    ]


def classify(plain, orig) -> str:
    st, data = read_all(plain)
    if st != "ok":
        return "DETECTED"
    if data == orig:
        return "UNDETECTED"
    if len(data) < len(orig) and orig.startswith(data):
        return "SILENT_TRUNCATION"
    return "SILENT_CORRUPTION"


def t_tamper(env: SecEnv) -> int:
    print("\n[+] Tamper detection (backing file modified out-of-band)")
    size = 3 * CHUNK_SIZE + 1000
    orig = env.make("tp", size)
    env.make("tp_other", size)
    cpath = env.c("tp")
    pristine = cpath.read_bytes()
    other = env.c("tp_other").read_bytes()
    st, back = read_all(env.p("tp"))
    if st != "ok" or back != orig:
        check("tamper", "baseline read before tampering", False, "cannot proceed")
        return 1
    fails = 0
    rows = []
    for name, expect, target, mut in tamper_cases():
        buf = bytearray(pristine)
        mut(buf, other)
        with open(cpath, "r+b") as f:
            f.write(buf)
            f.truncate(len(buf))
        time.sleep(env.settle)
        outcome = classify(env.p("tp"), orig)
        locality = ""
        if target is not None:
            oks = tot = 0
            for k in range(4):
                if k == target:
                    continue
                s, d = pread_fresh(env.p("tp"), k * CHUNK_SIZE, min(CHUNK_SIZE, size - k * CHUNK_SIZE))
                tot += 1
                oks += s == "ok" and d == orig[k * CHUNK_SIZE:k * CHUNK_SIZE + len(d)]
            locality = f" other chunks readable {oks}/{tot}"
        with open(cpath, "r+b") as f:  # restore
            f.write(pristine)
            f.truncate(len(pristine))
        time.sleep(env.settle)
        if outcome == "SILENT_CORRUPTION":
            ok = False
        elif expect == "detect":
            ok = outcome == "DETECTED"
        else:
            ok = None  # documented limitation: informational
        label = {"detect": "must detect", "limit": "known limitation"}[expect]
        r = check("tamper", name, ok, f"{outcome} ({label}){locality}")
        rows.append({"case": name, "expect": expect, "outcome": outcome})
        fails += r is False
    REPORT["metrics"]["tamper"] = rows
    if any(r["outcome"] == "UNDETECTED" and r["expect"] == "detect" for r in rows):
        print("    Hint: UNDETECTED may be a stale FUSE cache; increase --settle, run as root with "
              "--drop-caches, or mount with direct_io/attr_timeout=0.")
    return fails


def cmd_security(args) -> int:
    global DROP_CACHES, DIAG_MASTER
    DROP_CACHES = args.drop_caches
    if args.conf:
        try:
            pw = get_passphrase(args)
            wa = args.wrap_aad.encode() if args.wrap_aad else bytes.fromhex(args.wrap_aad_hex)
            DIAG_MASTER = unwrap_master(load_conf(args.conf), pw, wa)
            print("[+] Master key unwrapped: failing cases will be re-authenticated against the spec.")
        except ImportError:
            print("[-] --conf needs: pip install argon2-cffi cryptography (continuing without spec-auth)")
        except Exception as e:
            print(f"[-] could not unwrap master key ({type(e).__name__}); continuing without spec-auth")
    env = SecEnv(args.mount, args.backing, args.settle, args.seed)
    only = set(args.only.split(",")) if args.only else {"roundtrip", "edge", "fuzz", "nonce", "tamper"}
    fails = 0
    try:
        if "roundtrip" in only:
            fails += t_roundtrip(env)
        if "edge" in only:
            fails += t_edge(env, {int(x) for x in args.edge_case.split(',')} if args.edge_case else None)
        if "fuzz" in only:
            fails += t_fuzz(env, args.fuzz_ops, args.fuzz_seeds)
        if "nonce" in only:
            fails += t_nonce(env)
        if "tamper" in only:
            fails += t_tamper(env)
    except OSError as e:
        if e.errno != errno.ENOTCONN:
            raise
        fails += 1
        print(f"\n[FATAL] {e.strerror}")
        print("        The mount is gone (ENOTCONN): the LeichFS process crashed or exited.")
        print("        Remount, run it in the foreground (-f) to see the message, and check `dmesg | tail`.")
        print("        Typical causes: uncaught C++ exception (e.g. re-locking a std::shared_mutex),")
        print("        out-of-bounds access, or abort() from a failed assertion.")
    finally:
        if not args.keep:
            env.cleanup()
    print("\nNotes for the report:")
    print("  - AAD = magic||version||chunk_sz||salt||chunk_idx; plain_len is NOT authenticated, so")
    print("    truncation at a chunk boundary with a patched header is expected to go undetected")
    print("    (same limitation class as gocryptfs). Discuss it under 'Keterbatasan'.")
    print(f"\nSummary: {fails} failed checks")
    return 1 if fails else 0


# ---- Subcommand: bench --------------------------------------------------
def b_seq_write(path, size, bs, fsync):
    buf = memoryview(os.urandom(bs))
    t0 = time.perf_counter()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    done = 0
    while done < size:
        done += os.write(fd, buf[:min(bs, size - done)])
    if fsync:
        os.fsync(fd)
    os.close(fd)
    return size / (1 << 20) / (time.perf_counter() - t0)


def b_seq_read(path, bs):
    drop_cache(path)
    drop_system_caches()
    t0 = time.perf_counter()
    fd = os.open(path, os.O_RDONLY)
    n = 0
    while True:
        b = os.read(fd, bs)
        if not b:
            break
        n += len(b)
    os.close(fd)
    return n / (1 << 20) / (time.perf_counter() - t0)


def b_rand(path, size, ops, write, seed):
    rng = random.Random(seed)
    offs = [rng.randrange(0, size // 4096) * 4096 for _ in range(ops)]
    buf = os.urandom(4096)
    if not write:
        drop_cache(path)
    fd = os.open(path, os.O_RDWR)
    t0 = time.perf_counter()
    for o in offs:
        os.pwrite(fd, buf, o) if write else os.pread(fd, 4096, o)
    if write:
        os.fsync(fd)
    dt = time.perf_counter() - t0
    os.close(fd)
    return ops / dt


def b_par_write(root, total, n, bs, fsync):
    """Aggregate MiB/s of n concurrent writers, each to its own file (total bytes split evenly)."""
    import threading
    errs = []

    def worker(i):
        try:
            b_seq_write(root / f"par{i}.bin", total // n, bs, fsync)
        except OSError as e:
            errs.append(e)

    ts = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    t0 = time.perf_counter()
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    dt = time.perf_counter() - t0
    if errs:
        raise errs[0]
    return total / (1 << 20) / dt


class CpuProbe:
    """Cumulative CPU seconds (user+system, all threads) of a process, from /proc/<pid>/stat."""

    def __init__(self, pid: int):
        self.path = f"/proc/{pid}/stat"
        self.tck = os.sysconf("SC_CLK_TCK")
        self.read()  # fail early if the pid is wrong

    def read(self) -> float:
        with open(self.path) as f:
            data = f.read()
        fields = data[data.rindex(")") + 2:].split()  # fields[0] is field 3 (state)
        return (int(fields[11]) + int(fields[12])) / self.tck


def run_suite(root: Path, args, probe=None) -> dict:
    root.mkdir(parents=True, exist_ok=True)
    m = {}
    size = args.size_mib << 20
    big = root / "big.bin"
    def with_cpu(fn, *a):
        if probe is None:
            return fn(*a), None
        c0, t0 = probe.read(), time.perf_counter()
        r = fn(*a)
        wall = time.perf_counter() - t0
        return r, 100.0 * (probe.read() - c0) / wall

    for bs in args.block_sizes:
        v, cpu = with_cpu(b_seq_write, big, size, bs, not args.no_fsync)
        m[f"seq_write_MiBps_bs{bs}"] = v
        if cpu is not None:
            m[f"seq_write_daemon_cpu_pct_bs{bs}"] = cpu
        v, cpu = with_cpu(b_seq_read, big, bs)
        m[f"seq_read_MiBps_bs{bs}"] = v
        if cpu is not None:
            m[f"seq_read_daemon_cpu_pct_bs{bs}"] = cpu
    if args.par_writers > 1:
        m[f"par_write_MiBps_n{args.par_writers}"] = b_par_write(root, size, args.par_writers, 1 << 20,
                                                              not args.no_fsync)
    m["rand_read_4k_ops"] = b_rand(big, size, args.rand_ops, False, 1)
    m["rand_write_4k_ops"] = b_rand(big, size, args.rand_ops, True, 2)
    # open/close latency (HKDF per open() on LeichFS)
    small = root / "small.bin"
    write_file(small, b"x" * 4096)
    t0 = time.perf_counter()
    for _ in range(args.open_ops):
        os.close(os.open(small, os.O_RDONLY))
    m["open_close_us"] = (time.perf_counter() - t0) * 1e6 / args.open_ops
    # many small files
    d = root / "many"
    d.mkdir(exist_ok=True)
    n, payload = args.small_files, os.urandom(4096)
    t0 = time.perf_counter()
    for i in range(n):
        write_file(d / f"f{i}", payload, fsync=False)
    m["small_create_files_s"] = n / (time.perf_counter() - t0)
    t0 = time.perf_counter()
    for i in range(n):
        read_all(d / f"f{i}")
    m["small_read_files_s"] = n / (time.perf_counter() - t0)
    t0 = time.perf_counter()
    for i in range(n):
        os.stat(d / f"f{i}")
    m["small_stat_files_s"] = n / (time.perf_counter() - t0)
    t0 = time.perf_counter()
    for i in range(n):
        os.unlink(d / f"f{i}")
    m["small_unlink_files_s"] = n / (time.perf_counter() - t0)
    shutil.rmtree(root, ignore_errors=True)
    return m


def cmd_bench(args) -> int:
    global DROP_CACHES, BACKING_MAP
    DROP_CACHES = args.drop_caches
    if args.backing:
        BACKING_MAP = (Path(args.mount).resolve(), Path(args.backing).resolve())
    elif not (args.drop_caches and os.geteuid() == 0):
        print("[!] Read results are biased: LeichFS reads will hit the cached ciphertext file. "
              "Pass --backing <ciphertext dir> to evict it too.")
    targets = {"baseline": Path(args.baseline) / f"leichfs_bench_{os.getpid()}",
               "leichfs": Path(args.mount) / f"leichfs_bench_{os.getpid()}"}
    probe = CpuProbe(args.daemon_pid) if args.daemon_pid else None
    samples: dict[str, dict[str, list[float]]] = {t: {} for t in targets}
    raw = []
    total = args.warmup + args.reps
    for rep in range(total):
        order = list(targets) if rep % 2 == 0 else list(targets)[::-1]  # alternate to cancel drift
        for t in order:
            print(f"  rep {rep + 1}/{total} on {t}{' (warm-up, discarded)' if rep < args.warmup else ''}")
            os.sync()  # don't let the previous suite's dirty pages spill into this one
            if args.cooldown:
                time.sleep(args.cooldown)
            res = run_suite(targets[t], args, probe if t == "leichfs" else None)
            if rep >= args.warmup:
                for k, v in res.items():
                    samples[t].setdefault(k, []).append(v)
                    raw.append({"rep": rep, "target": t, "metric": k, "value": v})
    print(f"\n[+] Results (n={args.reps}; mean +/- 95% CI).  Ratio = LeichFS / baseline.")
    print(f"    {'metric':36} {'baseline':>20} {'leichfs':>20} {'ratio':>8}")
    table = {}
    for k in samples["leichfs"]:
        l = summarize(samples["leichfs"][k])
        if k not in samples["baseline"]:  # leichfs-only metric (e.g. daemon CPU %)
            table[k] = {"leichfs": l}
            print(f"    {k:36} {'-':>20} {l['mean']:>12.2f}+/-{l['ci95']:<7.2f} {'':>8}")
            continue
        b = summarize(samples["baseline"][k])
        ratio = l["mean"] / b["mean"] if b["mean"] else float("nan")
        table[k] = {"baseline": b, "leichfs": l, "ratio": ratio}
        print(f"    {k:36} {b['mean']:>12.2f}+/-{b['ci95']:<7.2f} {l['mean']:>12.2f}+/-{l['ci95']:<7.2f} "
              f"{ratio * 100:>7.1f}%")
    print("    (for *_us metrics lower is better, so ratio > 100% means slower)")
    REPORT["metrics"]["bench"] = table
    if args.csv:
        with open(args.csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["rep", "target", "metric", "value"])
            w.writeheader()
            w.writerows(raw)
        print(f"    raw samples -> {args.csv}")
    return 0


# ---- Subcommand: kdf ----------------------------------------------------
def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


def cmd_kdf(args) -> int:
    ok = hkdf_sha256(bytes([0x0b] * 22), bytes(range(13)), bytes(range(0xf0, 0xfa)), 42).hex()
    check("kdf", "HKDF-SHA256 matches RFC 5869 test case 1",
          ok == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
    mk, salt = os.urandom(32), os.urandom(16)
    n = args.hkdf_iters
    t0 = time.perf_counter()
    for _ in range(n):
        hkdf_sha256(mk, salt, INFO_KEY, KEY_SIZE)       # derive_file_material() does
        hkdf_sha256(mk, salt, INFO_NONCE, NONCE_SIZE)   # two HKDF calls per open()
    us = (time.perf_counter() - t0) * 1e6 / n
    print(f"[+] derive_file_material (2x HKDF-SHA256, Python reference): {us:.2f} us per open() "
          f"(C++/OpenSSL will be faster; use bench's open_close_us for the real number)")
    REPORT["metrics"]["hkdf_us"] = us
    try:
        from argon2.low_level import Type, hash_secret_raw
    except ImportError:
        print("[-] argon2-cffi not installed; `pip install argon2-cffi` for the Argon2id sweep.")
        return 0
    print(f"\n[+] Argon2id sweep (t=iterations, m=KiB, p=lanes), {args.reps} runs each")
    print(f"    {'t':>2} {'m KiB':>9} {'p':>2} {'mean ms':>10} {'sd':>8} {'ci95':>8}")
    rows = []
    configs = args.configs.split(";")
    if args.conf:
        c = load_conf(args.conf)
        configs.insert(0, f"{c['argon2_t']},{c['argon2_m']},{c['argon2_p']}")
        print(f"    (first row = parameters read from {args.conf})")
    for cfg in configs:
        t, m, p = (int(x) for x in cfg.split(","))
        times = []
        for _ in range(args.reps):
            pw, s = os.urandom(16), os.urandom(16)
            t0 = time.perf_counter()
            hash_secret_raw(pw, s, t, m, p, 32, Type.ID)
            times.append((time.perf_counter() - t0) * 1000)
        s = summarize(times)
        rows.append({"t": t, "m_kib": m, "p": p, **s})
        print(f"    {t:>2} {m:>9} {p:>2} {s['mean']:>10.1f} {s['sd']:>8.1f} {s['ci95']:>8.1f}")
    REPORT["metrics"]["argon2id"] = rows
    print("    Use YOUR params.hpp values; mount-time cost is one Argon2id run (KEK unwrap).")
    return 0


def aad_candidates(hdr: Header, idx: int):
    pre = hdr.aad(0)[:32]
    out = [("spec: prefix||be64(idx)", pre + struct.pack(">Q", idx))]
    for j in sorted(set(range(0, 9)) | {idx + 1} | ({idx - 1} if idx else set())):
        if j != idx:
            out.append((f"prefix||be64({j})  [wrong chunk index used when encrypting]", pre + struct.pack(">Q", j)))
    out += [
        ("prefix||le64(idx)", pre + struct.pack("<Q", idx)),
        ("prefix||be32(idx)", pre + struct.pack(">I", idx)),
        ("prefix||le32(idx)", pre + struct.pack("<I", idx)),
        ("prefix only (32 B, index not appended)", pre),
        ("prefix||8 zero bytes (index never filled in)", pre + bytes(8)),
        ("empty AAD", b""),
        ("zeroed salt inside prefix", pre[:16] + bytes(16) + struct.pack(">Q", idx)),
        ("version/chunk_sz little-endian in prefix",
         MAGIC + struct.pack("<II", hdr.version, hdr.chunk_size) + hdr.salt + struct.pack(">Q", idx)),
    ]
    return out


def explain_failure(rec: Record, hdr: Header, master: bytes, file_key: bytes) -> list[str]:
    """Which small variation of key / AAD / length would make this record authenticate?"""
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    keys = [("spec file_key", file_key), ("master key used directly", master),
            ("HKDF(info=nonce-base) used as the key", hkdf_sha256(master, hdr.salt, INFO_NONCE, KEY_SIZE))]
    raw = rec.ciphertext + rec.tag
    if not any(rec.tag):
        return ["stored tag is ALL ZEROS: the tag was written somewhere other than record offset "
                "12+plain_len (and may have overwritten ciphertext bytes). Check the tag_out pointer "
                "passed to aesgcm_encrypt"]
    hits = []
    for kn, k in keys:
        a = AESGCM(k)
        for an, aad in aad_candidates(hdr, rec.index):
            try:
                a.decrypt(rec.nonce, raw, aad)
                hits.append(f"key = {kn}; aad = {an}")
            except InvalidTag:
                pass
    if hits or len(rec.ciphertext) > 16384:
        return hits
    a, aad = AESGCM(file_key), hdr.aad(rec.index)
    for n in range(len(rec.ciphertext)):
        try:
            a.decrypt(rec.nonce, raw[:n + 16], aad)
            hits.append(f"record authenticates as a {n}-byte chunk (tag sits at record offset {12 + n}), "
                        f"but the slot holds {len(rec.ciphertext)} B: encryption used a different length than the write")
        except InvalidTag:
            pass
    return hits


# ---- Subcommand: verify (reference decryptor) ---------------------------
def load_conf(path) -> dict:
    conf = json.loads(Path(path).read_text())
    need = {"version", "kdf", "argon2_m", "argon2_t", "argon2_p",
            "salt", "wrapped_key", "wrap_nonce", "wrap_tag"}
    if need - conf.keys():
        raise FormatError(f"conf missing fields: {sorted(need - conf.keys())}")
    for k in ("salt", "wrapped_key", "wrap_nonce", "wrap_tag"):
        try:
            conf[k] = bytes.fromhex(conf[k])
        except ValueError:
            raise FormatError(f"conf field {k} is not valid hex")
    return conf


def get_passphrase(args) -> bytes:
    if args.passphrase_file:
        data = Path(args.passphrase_file).read_bytes()
        return data[:-1] if data.endswith(b"\n") else data
    env = os.environ.get("LEICHFS_PASSPHRASE")
    if env is not None:
        return env.encode()
    return getpass.getpass("LeichFS passphrase: ").encode()


def cmd_verify(args) -> int:
    global DROP_CACHES
    DROP_CACHES = args.drop_caches
    try:
        from argon2.low_level import Type, hash_secret_raw
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        print("[-] verify needs: pip install argon2-cffi cryptography")
        return 2
    g = "verify"
    conf = load_conf(args.conf)
    print(f"[+] Config {args.conf}")
    mode = Path(args.conf).stat().st_mode & 0o777
    fails = 0
    for r in (
        check(g, "conf permissions 0600", mode == 0o600, oct(mode)),
        check(g, "conf version == 1 and kdf == argon2id",
              conf["version"] == 1 and conf["kdf"] == "argon2id"),
        check(g, "wrapped_key/nonce/tag sizes = 32/12/16",
              (len(conf["wrapped_key"]), len(conf["wrap_nonce"]), len(conf["wrap_tag"])) == (32, 12, 16)),
        check(g, "conf salt size", None, f"{len(conf['salt'])} bytes; "
              f"argon2 m={conf['argon2_m']} KiB t={conf['argon2_t']} p={conf['argon2_p']}"),
    ):
        fails += r is False

    def kek_for(pw: bytes) -> bytes:
        return hash_secret_raw(pw, conf["salt"], conf["argon2_t"], conf["argon2_m"],
                               conf["argon2_p"], KEY_SIZE, Type.ID)

    def unwrap(kek: bytes) -> bytes:
        aad = (args.wrap_aad.encode() if args.wrap_aad else bytes.fromhex(args.wrap_aad_hex)) or None
        return AESGCM(kek).decrypt(conf["wrap_nonce"], conf["wrapped_key"] + conf["wrap_tag"], aad)

    pw = get_passphrase(args)
    t0 = time.perf_counter()
    kek = kek_for(pw)
    kdf_ms = (time.perf_counter() - t0) * 1000
    REPORT["metrics"]["argon2id_conf_ms"] = kdf_ms
    print(f"    Argon2id with the conf's real parameters: {kdf_ms:.1f} ms (mount-time cost)")
    try:
        master = unwrap(kek)
    except InvalidTag:
        check(g, "passphrase unwraps master key", False,
              "tag mismatch: wrong passphrase, or wrap AAD differs (set --wrap-aad to your WRAP_AAD)")
        return 1
    check(g, "passphrase unwraps master key (AES-256-GCM tag verified)", True)
    if not args.skip_negative:
        try:
            unwrap(kek_for(pw + b"x"))
            r = check(g, "wrong passphrase rejected", False, "unwrapped with wrong passphrase!")
        except InvalidTag:
            r = check(g, "wrong passphrase rejected", True)
        fails += r is False

    if args.mount:
        mp = os.path.ismount(args.mount)
        r = check(g, "--mount is an active mountpoint", mp,
                  args.mount if mp else f"{args.mount} is not a mountpoint - mount LeichFS there first")
        if mp is False:
            args.mount = None  # skip the per-file comparison instead of failing every file
        fails += r is False
    files = collect_files(args.paths)
    neg_done = False
    for path in files:
        try:
            hdr = read_header(path)
        except FormatError as e:
            print(f"\n[+] {path}: skipped ({e})")
            continue
        print(f"\n[+] {path} ({hdr.plain_length} B, {hdr.n_chunks} chunks)")
        file_key = hkdf_sha256(master, hdr.salt, INFO_KEY, KEY_SIZE)
        nonce_base = hkdf_sha256(master, hdr.salt, INFO_NONCE, NONCE_SIZE)
        aes = AESGCM(file_key)
        digest, bad, first, bad_recs = hashlib.sha256(), [], None, []
        total = 0
        hyp = {"design": 0, "xor_ctr": 0}
        masks = set()
        try:
            for rec in iter_records(path, hdr):
                total += 1
                first = first or rec
                ctr = struct.pack(">I", rec.index)
                hyp["design"] += rec.nonce[8:] == ctr                       # nonce = rand8||be32(idx)
                hyp["xor_ctr"] += bytes(a ^ b for a, b in zip(rec.nonce, nonce_base))[8:] == ctr
                masks.add(bytes(a ^ b for a, b in zip(rec.nonce[:8], nonce_base[:8])))
                try:
                    pt = aes.decrypt(rec.nonce, rec.ciphertext + rec.tag, hdr.aad(rec.index))
                except InvalidTag:
                    bad.append(rec.index)
                    if len(bad_recs) < 3:
                        bad_recs.append(rec)
                    continue
                if len(pt) != len(rec.ciphertext):
                    bad.append(rec.index)
                digest.update(pt)
        except FormatError as e:
            fails += check(g, "records parse", False, str(e)) is False
            continue
        r = check(g, "every chunk authenticates (key chain + AAD per DESIGN.md)", not bad,
                  "failed chunks: " + ",".join(map(str, bad[:20])) if bad else f"{total} chunks")
        fails += r is False
        if bad_recs and not args.no_explain:
            for br in bad_recs:
                hits = explain_failure(br, hdr, master, file_key)
                check(g, f"chunk {br.index}: what would make it authenticate?", None,
                      " | ".join(hits) if hits else
                      "nothing matched: the stored nonce/ciphertext/tag bytes themselves are inconsistent "
                      "(record overwritten after encryption, or a different nonce was used to encrypt than the one stored)")
        if total:
            check(g, "nonce layout: stored nonce[8:12] == be32(idx)  (DESIGN.md)", None,
                  f"{hyp['design']}/{total} chunks")
            check(g, "nonce layout: (stored nonce XOR nonce_base)[8:12] == be32(idx)", None,
                  f"{hyp['xor_ctr']}/{total} chunks (would show nonce_base masking the counter)")
            check(g, "nonce[:8] XOR nonce_base[:8] constant across chunks?", None,
                  f"{len(masks)} distinct values over {total} chunks (1 with >1 chunks = deterministic prefix)")
        if first and not neg_done:
            neg_done = True
            wrong_idx = AESGCM(file_key)
            for label, aad in (("chunk index", hdr.aad(first.index + 1)),
                               ("salt", hdr.aad(first.index)[:16] + bytes(16) + hdr.aad(first.index)[32:])):
                try:
                    wrong_idx.decrypt(first.nonce, first.ciphertext + first.tag, aad)
                    r = check(g, f"AAD binding: wrong {label} rejected", False)
                except InvalidTag:
                    r = check(g, f"AAD binding: wrong {label} rejected", True)
                fails += r is False
        if args.mount and args.root and not bad:
            rel = Path(path).relative_to(args.root)
            st, data = read_all(Path(args.mount) / rel)
            ok = st == "ok" and hashlib.sha256(data).digest() == digest.digest()
            r = check(g, "mounted FS output == reference decryption", ok,
                      f"sha256 {digest.hexdigest()[:16]}.." if ok else
                      (f"read via mount failed: {errno.errorcode.get(data, data)} "
                       f"({os.strerror(data) if isinstance(data, int) and data > 0 else '?'})"
                       if st == "err" else "plaintext differs from reference decryption"))
            fails += r is False
    print(f"\nSummary: {fails} failed checks")
    return 1 if fails else 0


# ---- CLI ----------------------------------------------------------------
def mount_info(path):
    real = os.path.realpath(path)
    best = None
    try:
        with open("/proc/self/mountinfo") as f:
            for line in f:
                parts = line.split()
                mp = parts[4].replace("\\040", " ")
                if real == mp or real.startswith(mp.rstrip("/") + "/"):
                    if best is None or len(mp) > len(best[0]):
                        sep = parts.index("-")
                        best = (mp, parts[5], parts[sep + 1], parts[sep + 2], parts[sep + 3])
    except (OSError, ValueError, IndexError):
        return None
    if not best:
        return None
    return {"mountpoint": best[0], "mount_options": best[1], "fstype": best[2],
            "source": best[3], "super_options": best[4]}


def capture_env(args) -> dict:
    u = os.uname()
    env = {"date": time.strftime("%Y-%m-%d %H:%M:%S"), "python": sys.version.split()[0],
           "kernel": u.release, "machine": u.machine, "cpu_count": os.cpu_count()}
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith("model name"):
                    env["cpu"] = line.split(":", 1)[1].strip()
                    break
        with open("/proc/meminfo") as f:
            env["mem_total_kib"] = int(f.readline().split()[1])
    except (OSError, ValueError, IndexError):
        pass
    try:
        with open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor") as f:
            env["cpu_governor"] = f.read().strip()
    except OSError:
        pass
    paths = {k: mount_info(getattr(args, k)) for k in ("mount", "backing", "baseline") if getattr(args, k, None)}
    if paths:
        env["paths"] = paths
    return env


def build_parser():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", help="write all checks/metrics to this JSON file")
    ap.add_argument("--label", help="free-text name stored in the JSON (e.g. 'raw', '+no-fdatasync')")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("format", help="validate header/records")
    s.add_argument("paths", nargs="+")
    s.set_defaults(fn=cmd_format)

    s = sub.add_parser("randomness", help="ciphertext randomness tests")
    s.add_argument("paths", nargs="+")
    s.add_argument("--max-bytes", type=int, default=16 << 20)
    s.set_defaults(fn=cmd_randomness)

    s = sub.add_parser("compare", help="compare two encrypted files")
    s.add_argument("a")
    s.add_argument("b")
    s.set_defaults(fn=cmd_compare)

    s = sub.add_parser("overhead", help="storage overhead vs. model")
    s.add_argument("--backing")
    s.add_argument("--mount")
    s.add_argument("--limit", type=int, default=50)
    s.set_defaults(fn=cmd_overhead)

    s = sub.add_parser("security", help="functional + tamper tests on a mounted FS")
    s.add_argument("--mount", required=True)
    s.add_argument("--backing", required=True)
    s.add_argument("--settle", type=float, default=1.5, help="seconds to wait for FUSE attr cache")
    s.add_argument("--fuzz-ops", type=int, default=150)
    s.add_argument("--fuzz-seeds", type=int, default=5)
    s.add_argument("--conf", help="path to .leichfs.conf: re-authenticate failing backing files against the spec")
    s.add_argument("--passphrase-file", help="else $LEICHFS_PASSPHRASE, else prompt (with --conf)")
    s.add_argument("--wrap-aad", default="leichfs-key-wrap", help="WRAP_AAD string (default: leichfs-key-wrap)")
    s.add_argument("--wrap-aad-hex", default="")
    s.add_argument("--edge-case", help="comma list of edge case indices to run (0-based), e.g. 0 or 0,3")
    s.add_argument("--only", help="comma list of: roundtrip,edge,fuzz,nonce,tamper (default all)")
    s.add_argument("--seed", type=int, default=42)
    s.add_argument("--drop-caches", action="store_true", help="drop page cache (root only)")
    s.add_argument("--keep", action="store_true", help="keep test files")
    s.set_defaults(fn=cmd_security)

    s = sub.add_parser("bench", help="performance vs baseline directory")
    s.add_argument("--mount", required=True)
    s.add_argument("--baseline", required=True, help="dir on the same filesystem as --backing")
    s.add_argument("--daemon-pid", type=int, help="pid of the leichfs daemon, e.g. $(pgrep -n leichfs): "
                   "reports its CPU %% during sequential phases (CPU-bound or waiting?)")
    s.add_argument("--backing", help="ciphertext dir behind --mount: evicted from page cache before cold reads")
    s.add_argument("--reps", type=int, default=10)
    s.add_argument("--warmup", type=int, default=1)
    s.add_argument("--size-mib", type=int, default=64)
    s.add_argument("--block-sizes", type=lambda x: [int(v) for v in x.split(",")],
                   default=[4096, 65536, 1 << 20])
    s.add_argument("--rand-ops", type=int, default=2000)
    s.add_argument("--open-ops", type=int, default=2000)
    s.add_argument("--small-files", type=int, default=1000)
    s.add_argument("--no-fsync", action="store_true")
    s.add_argument("--cooldown", type=float, default=0.0,
                   help="seconds to sleep before each suite run (lets an SSD flush its SLC cache)")
    s.add_argument("--par-writers", type=int, default=0,
                   help="also measure aggregate throughput of N concurrent writers on separate files (0=off)")
    s.add_argument("--drop-caches", action="store_true")
    s.add_argument("--csv")
    s.set_defaults(fn=cmd_bench)

    s = sub.add_parser("verify", help="reference decryptor / independent verification")
    s.add_argument("--conf", required=True, help="path to .leichfs.conf")
    s.add_argument("paths", nargs="+", help="backing files or directories")
    s.add_argument("--passphrase-file", help="else $LEICHFS_PASSPHRASE, else prompt")
    s.add_argument("--wrap-aad", default="", help="WRAP_AAD string literal from your source (no trailing NUL)")
    s.add_argument("--wrap-aad-hex", default="", help="same, as hex (use if it has non-text bytes)")
    s.add_argument("--skip-negative", action="store_true", help="skip wrong-passphrase test (saves one Argon2 run)")
    s.add_argument("--no-explain", action="store_true", help="do not try AAD/key/length variations on failing chunks")
    s.add_argument("--mount", help="plaintext mount, to compare against reference decryption")
    s.add_argument("--root", help="backing root dir (maps backing paths to mount paths)")
    s.add_argument("--drop-caches", action="store_true")
    s.set_defaults(fn=cmd_verify)

    s = sub.add_parser("kdf", help="Argon2id / HKDF timing")
    s.add_argument("--configs", default="2,19456,1;1,47104,1;3,65536,4;4,262144,4")
    s.add_argument("--reps", type=int, default=10)
    s.add_argument("--hkdf-iters", type=int, default=20000)
    s.add_argument("--conf", help="also time the real Argon2id parameters from .leichfs.conf")
    s.set_defaults(fn=cmd_kdf)
    return ap


def main() -> int:
    args = build_parser().parse_args()
    if args.label:
        REPORT["label"] = args.label
    REPORT["env"] = capture_env(args)
    try:
        rc = args.fn(args)
    except (OSError, FormatError) as e:
        print(f"[-] Error: {e}")
        rc = 2
    if args.json:
        with open(args.json, "w") as f:
            json.dump(REPORT, f, indent=2, default=str)
        print(f"[+] JSON report -> {args.json}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
