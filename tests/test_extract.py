"""Unit tests for virtual-offset extraction from audited archives."""

from __future__ import annotations

import hashlib
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.bgzf import (  # noqa: E402
    EOF_MEMBER,
    MAX_EXTRACT_SIZE,
    AuditError,
    extract,
    parse_virtual_offset,
)
from tests.bgzf_fixtures import bgzf_block, build_archive, build_index  # noqa: E402


def voffset(block_start: int, inner: int) -> int:
    return (block_start << 16) | inner


class ParseVirtualOffsetTests(unittest.TestCase):
    def test_valid_decimal_uint64(self):
        self.assertEqual(parse_virtual_offset(b"0", "virtualStart"), 0)
        self.assertEqual(parse_virtual_offset(b"007", "virtualStart"), 7)
        self.assertEqual(
            parse_virtual_offset(b"18446744073709551615", "virtualEnd"),
            (1 << 64) - 1,
        )

    def test_rejects_non_decimal(self):
        for raw in (b"", b"abc", b"-1", b"+1", b"1.5", b" 1", b"1 ", b"0x10", "１２".encode()):
            with self.assertRaises(AuditError) as ctx:
                parse_virtual_offset(raw, "virtualStart")
            self.assertEqual(ctx.exception.code, "BAD_VIRTUAL_OFFSET", raw)
            self.assertIsNone(ctx.exception.offset)

    def test_rejects_beyond_uint64(self):
        with self.assertRaises(AuditError) as ctx:
            parse_virtual_offset(b"18446744073709551616", "virtualEnd")
        self.assertEqual(ctx.exception.code, "BAD_VIRTUAL_OFFSET")


class ExtractTests(unittest.TestCase):
    payloads = [b"aaaa", b"bbbb", b"cccc"]

    def setUp(self):
        self.archive = build_archive(self.payloads)
        self.index = build_index(self.archive, self.payloads)
        self.starts: list[int] = []
        pos = 0
        for payload in self.payloads:
            self.starts.append(pos)
            pos += len(bgzf_block(payload))
        self.eof_start = pos
        self.assertEqual(self.archive[self.eof_start:], EOF_MEMBER)

    def expect(self, archive, index, vs, ve, code, offset=None):
        with self.assertRaises(AuditError) as ctx:
            extract(archive, index, vs, ve)
        self.assertEqual(ctx.exception.code, code)
        if offset is not None:
            self.assertEqual(ctx.exception.offset, offset)
        return ctx.exception

    def test_single_block_slice(self):
        vs, ve = voffset(self.starts[1], 1), voffset(self.starts[1], 3)
        result = extract(self.archive, self.index, vs, ve)
        self.assertEqual(result.data, b"bb")
        self.assertEqual(result.virtual_start, vs)
        self.assertEqual(result.virtual_end, ve)
        self.assertEqual(result.sha256, hashlib.sha256(b"bb").hexdigest())

    def test_cross_block_concatenation_in_archive_order(self):
        result = extract(
            self.archive,
            self.index,
            voffset(self.starts[0], 2),
            voffset(self.starts[2], 3),
        )
        self.assertEqual(result.data, b"aa" + b"bbbb" + b"ccc")

    def test_whole_archive_via_eof_end(self):
        result = extract(self.archive, self.index, 0, voffset(self.eof_start, 0))
        self.assertEqual(result.data, b"aaaabbbbcccc")

    def test_empty_range_is_allowed(self):
        point = voffset(self.starts[1], 2)
        result = extract(self.archive, self.index, point, point)
        self.assertEqual(result.data, b"")
        self.assertEqual(result.sha256, hashlib.sha256(b"").hexdigest())

    def test_end_at_block_start_excludes_that_block(self):
        result = extract(self.archive, self.index, 0, voffset(self.starts[1], 0))
        self.assertEqual(result.data, b"aaaa")

    def test_audit_failure_is_not_bypassed(self):
        # A corrupt archive must fail with the audit error even when the
        # requested endpoints themselves are perfectly canonical.
        broken = b"XX" + self.archive[2:]
        self.expect(broken, self.index, 0, voffset(self.eof_start, 0), "BAD_MAGIC", 0)

    def test_block_address_must_be_member_start(self):
        # Byte 3 sits inside block 0, not on a member boundary.
        self.expect(
            self.archive,
            self.index,
            voffset(3, 0),
            voffset(self.starts[1], 0),
            "VIRTUAL_OFFSET_NOT_BLOCK_START",
        )

    def test_within_block_offset_must_be_canonical(self):
        # Block payloads are 4 bytes: inner offset 4 must be written as
        # the next block's start (or the EOF start) instead.
        self.expect(
            self.archive,
            self.index,
            voffset(self.starts[0], 4),
            voffset(self.eof_start, 0),
            "VIRTUAL_OFFSET_NOT_CANONICAL",
            self.starts[0],
        )

    def test_eof_start_is_not_a_valid_range_start(self):
        self.expect(
            self.archive,
            self.index,
            voffset(self.eof_start, 0),
            voffset(self.eof_start, 0),
            "VIRTUAL_OFFSET_NOT_CANONICAL",
            self.eof_start,
        )

    def test_eof_end_requires_zero_inner_offset(self):
        self.expect(
            self.archive,
            self.index,
            0,
            voffset(self.eof_start, 1),
            "VIRTUAL_OFFSET_NOT_CANONICAL",
            self.eof_start,
        )

    def test_reversed_range(self):
        self.expect(
            self.archive,
            self.index,
            voffset(self.starts[2], 0),
            voffset(self.starts[1], 0),
            "VIRTUAL_OFFSETS_REVERSED",
        )

    def test_exactly_one_mib_is_allowed(self):
        payloads = [b"x" * 65536] * 16  # 16 * 64 KiB = 1 MiB
        archive = build_archive(payloads)
        index = build_index(archive, payloads)
        eof = len(archive) - len(EOF_MEMBER)
        result = extract(archive, index, 0, voffset(eof, 0))
        self.assertEqual(len(result.data), MAX_EXTRACT_SIZE)

    def test_over_limit_returns_no_partial_bytes(self):
        payloads = [b"x" * 65536] * 17  # 17 * 64 KiB > 1 MiB
        archive = build_archive(payloads)
        index = build_index(archive, payloads)
        eof = len(archive) - len(EOF_MEMBER)
        self.expect(archive, index, 0, voffset(eof, 0), "EXTRACT_TOO_LARGE")


if __name__ == "__main__":
    unittest.main(verbosity=2)
