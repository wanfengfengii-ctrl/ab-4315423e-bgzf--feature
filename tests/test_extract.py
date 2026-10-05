"""Unit tests for BGZF virtual-offset extraction."""

from __future__ import annotations

import hashlib
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.bgzf import (  # noqa: E402
    MAX_EXTRACT_SIZE,
    AuditError,
    extract,
)
from tests.bgzf_fixtures import bgzf_block, build_archive, build_index  # noqa: E402


def vo(compressed_start: int, block_offset: int = 0) -> int:
    """Pack a BGZF virtual offset."""
    return (compressed_start << 16) | block_offset


class ExtractFixture(unittest.TestCase):
    PAYLOADS = [b"block-zero", b"block-one!!", b"block-two"]

    def setUp(self):
        self.payloads = list(self.PAYLOADS)
        self.archive = build_archive(self.payloads)
        self.index = build_index(self.archive, self.payloads)
        sizes = [len(bgzf_block(p)) for p in self.payloads]
        self.starts = [0]
        for size in sizes[:-1]:
            self.starts.append(self.starts[-1] + size)
        self.eof_start = self.starts[-1] + sizes[-1]
        self.starts = tuple(self.starts)

    def extract(self, start, end):
        return extract(self.archive, self.index, start, end)

    def expect_fail(self, start, end, code):
        with self.assertRaises(AuditError) as ctx:
            self.extract(start, end)
        self.assertEqual(ctx.exception.code, code)
        return ctx.exception


class ValidExtractionTests(ExtractFixture):
    def test_single_block_prefix(self):
        data, start, end = self.extract(vo(self.starts[0], 0), vo(self.starts[0], 5))
        self.assertEqual(data, b"block")
        self.assertEqual(start, vo(self.starts[0], 0))
        self.assertEqual(end, vo(self.starts[0], 5))

    def test_single_block_inner_slice(self):
        data, _, _ = self.extract(vo(self.starts[1], 6), vo(self.starts[1], 9))
        self.assertEqual(data, b"one")

    def test_single_block_to_end_of_block(self):
        # Ending on the next block's start covers the whole first block.
        data, _, _ = self.extract(vo(self.starts[0], 0), vo(self.starts[1], 0))
        self.assertEqual(data, b"block-zero")

    def test_cross_block_slice_in_archive_order(self):
        data, start, end = self.extract(
            vo(self.starts[0], 6), vo(self.starts[2], 5)
        )
        self.assertEqual(data, b"zero" + b"block-one!!" + b"block")
        self.assertEqual(start, vo(self.starts[0], 6))
        self.assertEqual(end, vo(self.starts[2], 5))

    def test_to_eof_member_start(self):
        data, start, end = self.extract(vo(self.starts[2], 6), vo(self.eof_start))
        self.assertEqual(data, b"two")
        self.assertEqual(start, vo(self.starts[2], 6))
        self.assertEqual(end, vo(self.eof_start))

    def test_whole_stream(self):
        data, _, _ = self.extract(vo(self.starts[0]), vo(self.eof_start))
        self.assertEqual(data, b"".join(self.payloads))
        self.assertEqual(
            hashlib.sha256(data).hexdigest(),
            hashlib.sha256(b"".join(self.payloads)).hexdigest(),
        )

    def test_empty_interval_within_block(self):
        data, start, end = self.extract(
            vo(self.starts[1], 3), vo(self.starts[1], 3)
        )
        self.assertEqual(data, b"")
        self.assertEqual(start, end)

    def test_empty_interval_on_block_boundary(self):
        data, _, _ = self.extract(vo(self.starts[1]), vo(self.starts[1]))
        self.assertEqual(data, b"")

    def test_data_sha256_header_input(self):
        data, _, _ = self.extract(vo(self.starts[0]), vo(self.eof_start))
        self.assertEqual(
            hashlib.sha256(data).hexdigest(),
            hashlib.sha256(b"".join(self.payloads)).hexdigest(),
        )


class InvalidEndpointTests(ExtractFixture):
    def test_inner_offset_past_payload_end(self):
        self.expect_fail(
            vo(self.starts[0], 99), vo(self.starts[1]), "VIRTUAL_OFFSET_OUT_OF_RANGE"
        )
        self.expect_fail(
            vo(self.starts[0]), vo(self.starts[0], 99), "VIRTUAL_OFFSET_OUT_OF_RANGE"
        )

    def test_block_end_named_as_inner_position_is_not_canonical(self):
        # The end of block 0 must be named (block1_start, 0), not
        # (block0_start, len(block0)).
        self.expect_fail(
            vo(self.starts[0], 10), vo(self.starts[1]), "VIRTUAL_OFFSET_NOT_CANONICAL"
        )
        self.expect_fail(
            vo(self.starts[0]), vo(self.starts[0], 10), "VIRTUAL_OFFSET_NOT_CANONICAL"
        )

    def test_compressed_start_mid_member(self):
        # Offset 5 lands inside the first member's header, not on a block.
        self.expect_fail(vo(5), vo(self.eof_start), "VIRTUAL_OFFSET_NOT_CANONICAL")

    def test_compressed_start_past_archive(self):
        self.expect_fail(
            vo(self.eof_start + 1000), vo(self.eof_start), "VIRTUAL_OFFSET_NOT_CANONICAL"
        )

    def test_start_on_eof_member(self):
        self.expect_fail(
            vo(self.eof_start), vo(self.eof_start), "VIRTUAL_OFFSET_NOT_CANONICAL"
        )

    def test_eof_member_with_inner_offset(self):
        self.expect_fail(
            vo(self.starts[2]), vo(self.eof_start, 1), "VIRTUAL_OFFSET_NOT_CANONICAL"
        )

    def test_reversed_within_block(self):
        self.expect_fail(
            vo(self.starts[0], 5), vo(self.starts[0], 2), "VIRTUAL_OFFSET_REVERSED"
        )

    def test_reversed_across_blocks(self):
        self.expect_fail(
            vo(self.starts[2], 1), vo(self.starts[1], 1), "VIRTUAL_OFFSET_REVERSED"
        )

    def test_unsigned_64_bit_bounds(self):
        self.expect_fail(-1, vo(self.eof_start), "BAD_VIRTUAL_OFFSET")
        self.expect_fail(vo(0), 2**64, "BAD_VIRTUAL_OFFSET")
        self.expect_fail(2**64, 2**64 + 1, "BAD_VIRTUAL_OFFSET")


class ExtractLimitTests(unittest.TestCase):
    def test_exactly_one_mebibyte_is_allowed(self):
        # Highly compressible data keeps the archive under the 8 MiB cap.
        payloads = [b"\0" * 60000 for _ in range(20)]
        archive = build_archive(payloads)
        index = build_index(archive, payloads)
        sizes = [len(bgzf_block(p)) for p in payloads]
        starts = [0]
        for size in sizes[:-1]:
            starts.append(starts[-1] + size)
        eof_start = starts[-1] + sizes[-1]
        end_inner = MAX_EXTRACT_SIZE - 17 * 60000

        data, _, _ = extract(archive, index, vo(0), vo(starts[17], end_inner))
        self.assertEqual(len(data), MAX_EXTRACT_SIZE)

        with self.assertRaises(AuditError) as ctx:
            extract(archive, index, vo(0), vo(starts[17], end_inner + 1))
        self.assertEqual(ctx.exception.code, "EXTRACT_TOO_LARGE")

        with self.assertRaises(AuditError) as ctx:
            extract(archive, index, vo(0), vo(eof_start))
        self.assertEqual(ctx.exception.code, "EXTRACT_TOO_LARGE")


class ExtractAuditGuardTests(ExtractFixture):
    def test_corrupt_archive_never_serves_bytes(self):
        block0_len = len(bgzf_block(self.payloads[0]))
        broken = bytearray(self.archive)
        struct.pack_into("<I", broken, block0_len - 8, 0xDEADBEEF)
        with self.assertRaises(AuditError) as ctx:
            extract(bytes(broken), self.index, vo(0), vo(self.eof_start))
        self.assertEqual(ctx.exception.code, "CRC32_MISMATCH")

    def test_bad_index_never_serves_bytes(self):
        bad_index = bytearray(self.index)
        if len(bad_index) >= 16:
            struct.pack_into("<Q", bad_index, 8, 0)  # block 1 compressed offset
        with self.assertRaises(AuditError) as ctx:
            extract(self.archive, bytes(bad_index), vo(0), vo(self.eof_start))
        self.assertEqual(ctx.exception.code, "INDEX_COMPRESSED_OFFSET_MISMATCH")


class EmptyDataBlockExtractionTests(unittest.TestCase):
    def test_offset_on_empty_data_block_is_valid(self):
        empty = bgzf_block(b"", level=1)  # non-canonical XFL: ordinary data
        second = bgzf_block(b"after")
        from app.bgzf import EOF_MEMBER

        archive = empty + second + EOF_MEMBER
        index = struct.pack("<Q", 1) + struct.pack("<QQ", len(empty), 0)

        data, _, _ = extract(archive, index, vo(0), vo(len(empty) + len(second)))
        self.assertEqual(data, b"after")

        # Inner offset on a zero-length block other than 0 is impossible.
        with self.assertRaises(AuditError) as ctx:
            extract(archive, index, vo(0, 1), vo(len(empty) + len(second)))
        self.assertEqual(ctx.exception.code, "VIRTUAL_OFFSET_OUT_OF_RANGE")


if __name__ == "__main__":
    unittest.main(verbosity=2)
