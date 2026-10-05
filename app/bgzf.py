"""BGZF (Blocked GNU Zip Format) validation and index auditing.

A BGZF archive is a concatenation of gzip members.  Every member is a
complete gzip block carrying one ``BC`` extra subfield that declares the
total member size minus one (``BSIZE``).  Deflate data lives in its own
zlib "raw" stream per member, which makes every block independently
seekable.  A valid archive ends with exactly one canonical 28-byte empty
member (the BGZF EOF sentinel) and has no trailing bytes.

The companion index is a little-endian unsigned 64-bit structure::

    uint64 count
    (uint64 compressed_start, uint64 uncompressed_start) * count

with one entry for every data block except the first, recording the
block's compressed-file offset and the cumulative decompressed offset at
which its payload begins.

Audited archives are also random-accessible through BGZF *virtual
offsets*: ``compressed_member_start << 16 | block_internal_offset``.
:func:`extract` re-audits archive and index before slicing, so only
fully audited bytes can ever leave the service.
"""

from __future__ import annotations

import hashlib
import struct
import zlib
from dataclasses import dataclass

# Limits imposed by the platform.
MAX_ARCHIVE_SIZE = 8 * 1024 * 1024  # 8 MiB compressed archive
MAX_DATA_BLOCKS = 4096
MAX_EXTRACT_SIZE = 1 * 1024 * 1024  # 1 MiB decompressed payload per extraction

# BGZF virtual offsets pack the compressed member start into the high 48
# bits and the block-internal uncompressed position into the low 16 bits.
VIRTUAL_OFFSET_SHIFT = 16
VIRTUAL_OFFSET_MASK = 0xFFFF
UINT64_MAX = (1 << 64) - 1

# Canonical BGZF EOF member: an empty block produced by every conformant
# writer (htslib, bgzip, ...).
EOF_MEMBER = bytes.fromhex(
    "1f8b08040000000000ff0600424302001b0003000000000000000000"
)

GZIP_ID1 = 0x1F
GZIP_ID2 = 0x8B
CM_DEFLATE = 8
FLG_FEXTRA = 4


class AuditError(Exception):
    """Validation failure carrying a stable code and a compressed offset.

    ``offset`` is the first locatable byte position in the compressed
    archive involved in the failure (or ``None`` when the problem cannot
    be pinned to a particular byte, e.g. a malformed index header).
    """

    def __init__(self, code: str, message: str, offset: int | None = None):
        super().__init__(message)
        self.code = code
        self.offset = offset


@dataclass(frozen=True)
class AuditResult:
    data_blocks: int
    uncompressed_length: int
    sha256: str  # hex digest of the concatenated decompressed payload


@dataclass(frozen=True)
class Block:
    """One audited data block: compressed extent and decompressed payload."""

    start: int
    end: int
    payload: bytes


@dataclass(frozen=True)
class AuditedArchive:
    """A fully validated archive, ready for virtual-offset access."""

    archive: bytes
    blocks: tuple[Block, ...]  # data blocks only (the EOF member excluded)
    eof_start: int
    uncompressed_length: int

    @property
    def sha256(self) -> str:
        digest = hashlib.sha256()
        for block in self.blocks:
            digest.update(block.payload)
        return digest.hexdigest()

    def audit_result(self) -> AuditResult:
        return AuditResult(
            data_blocks=len(self.blocks),
            uncompressed_length=self.uncompressed_length,
            sha256=self.sha256,
        )


def _fail(code: str, message: str, offset: int) -> "AuditError":
    return AuditError(code, message, offset)


def _parse_bgzf_member(data: bytes, start: int) -> tuple[int, bytes, int]:
    """Parse one BGZF member beginning at ``start``.

    Returns ``(member_end, payload, declared_isize)``.  Raises
    :class:`AuditError` on any inconsistency.
    """
    total = len(data)

    # --- Fixed gzip header (10 bytes) ---
    # Check magic first: a short garbage fragment points at byte 0 as a
    # bad member start, not as a truncated header.
    if start + 2 > total:
        raise _fail(
            "TRUNCATED_HEADER",
            "incomplete gzip header: need at least the 2-byte magic",
            start,
        )
    if data[start] != GZIP_ID1 or data[start + 1] != GZIP_ID2:
        raise _fail("BAD_MAGIC", "not a gzip member (missing 1f 8b magic)", start)
    if start + 10 > total:
        raise _fail(
            "TRUNCATED_HEADER",
            "incomplete gzip header: need 10 bytes",
            start,
        )
    cm, flg = data[start + 2], data[start + 3]
    if cm != CM_DEFLATE:
        raise _fail("BAD_COMPRESSION_METHOD", f"unsupported compression method {cm}", start)
    if not (flg & FLG_FEXTRA):
        raise _fail("MISSING_BC_FIELD", "gzip member has no FEXTRA fields", start)

    # --- FEXTRA: XLEN + subfields ---
    if start + 12 > total:
        raise _fail("TRUNCATED_HEADER", "incomplete FEXTRA length field", start)
    (xlen,) = struct.unpack_from("<H", data, start + 10)
    extra_start = start + 12
    extra_end = extra_start + xlen
    if extra_end > total:
        raise _fail("TRUNCATED_HEADER", "FEXTRA payload runs past end of archive", start)

    bsize: int | None = None
    p = extra_start
    while p + 4 <= extra_end:
        si1, si2 = data[p], data[p + 1]
        (slen,) = struct.unpack_from("<H", data, p + 2)
        field_data = p + 4
        field_end = field_data + slen
        if field_end > extra_end:
            raise _fail(
                "BAD_EXTRA_FIELD",
                "extra subfield length exceeds XLEN",
                p,
            )
        if si1 == ord("B") and si2 == ord("C"):
            if bsize is not None:
                raise _fail("DUPLICATE_BC_FIELD", "member contains more than one BC subfield", p)
            if slen != 2:
                raise _fail(
                    "BAD_BC_FIELD",
                    f"BC subfield must be 2 bytes, got {slen}",
                    p,
                )
            (bsize,) = struct.unpack_from("<H", data, field_data)
        p = field_end
    if p != extra_end:
        raise _fail("BAD_EXTRA_FIELD", "trailing bytes inside FEXTRA payload", p)
    if bsize is None:
        raise _fail("MISSING_BC_FIELD", "member has no BC (block size) subfield", start)

    # BSIZE is "total BGZF block size - 1".
    declared_member_size = bsize + 1
    member_end = start + declared_member_size
    if declared_member_size < 28:
        # Smallest legal member is the 28-byte empty EOF block.
        raise _fail(
            "BAD_BLOCK_SIZE",
            f"declared block size {declared_member_size} is below minimum 28",
            start,
        )
    if member_end > total:
        raise _fail(
            "BLOCK_SIZE_OVERRUN",
            f"declared block size {declared_member_size} runs past end of archive",
            start,
        )

    # Header flags other than FEXTRA (text/name/comment/hcrc) would mean the
    # header layout is no longer the fixed BGZF layout; reject them.
    allowed_flg = FLG_FEXTRA
    if flg & ~allowed_flg:
        raise _fail("UNSUPPORTED_HEADER_FLAGS", "BGZF members may only set FEXTRA", start)

    # --- Deflate stream and gzip trailer ---
    deflate_start = extra_end
    trailer = member_end - 8
    if trailer < deflate_start:
        raise _fail("BAD_BLOCK_SIZE", "declared block too short for deflate stream and trailer", start)

    decompressor = zlib.decompressobj(wbits=-15)  # raw deflate, no zlib/gzip wrapper
    try:
        payload = decompressor.decompress(data[deflate_start:trailer])
        payload += decompressor.flush()
    except zlib.error as exc:
        raise _fail("BAD_DEFLATE", f"deflate error: {exc}", deflate_start) from exc

    if not decompressor.eof:
        # The deflate stream did not terminate within the bytes the block
        # size allows: declared size / deflate boundary mismatch.
        raise _fail(
            "DEFLATE_NOT_TERMINATED",
            "deflate stream is not terminated within declared block",
            deflate_start,
        )
    # Unconsumed bytes between the end of the deflate stream and the trailer
    # are not permitted inside one member.
    if decompressor.unused_data:
        boundary = trailer - len(decompressor.unused_data)
        raise _fail(
            "DEFLATE_BOUNDARY_MISMATCH",
            "extra bytes found between deflate end and gzip trailer",
            boundary,
        )

    crc_stored, isize_stored = struct.unpack_from("<II", data, trailer)
    crc_actual = zlib.crc32(payload) & 0xFFFFFFFF
    if crc_stored != crc_actual:
        raise _fail(
            "CRC32_MISMATCH",
            f"stored CRC32 {crc_stored:08x} does not match payload {crc_actual:08x}",
            trailer,
        )
    isize_actual = len(payload) & 0xFFFFFFFF
    if isize_stored != isize_actual:
        raise _fail(
            "ISIZE_MISMATCH",
            f"stored ISIZE {isize_stored} does not match payload length {isize_actual}",
            trailer + 4,
        )

    return member_end, payload, isize_stored


def audit_archive(archive: bytes, index: bytes) -> AuditedArchive:
    """Validate a BGZF archive together with its companion block index.

    Raises :class:`AuditError` on the first problem, positioned at the
    first locatable compressed offset.  Returns the parsed blocks so
    callers can serve audited byte ranges without reparsing.
    """
    if len(archive) > MAX_ARCHIVE_SIZE:
        raise AuditError(
            "ARCHIVE_TOO_LARGE",
            f"archive is {len(archive)} bytes, limit is {MAX_ARCHIVE_SIZE}",
            None,
        )
    if not archive:
        raise AuditError("EMPTY_ARCHIVE", "archive is empty", 0)

    # Parse every member first, recording payloads and offsets.
    members: list[tuple[int, int, bytes]] = []  # (start, end, payload)
    pos = 0
    while pos < len(archive):
        end, payload, _isize = _parse_bgzf_member(archive, pos)
        members.append((pos, end, payload))
        pos = end

    # The final member must be exactly the canonical EOF sentinel.
    eof_start, eof_end, eof_payload = members[-1]
    if eof_payload or archive[eof_start:eof_end] != EOF_MEMBER:
        raise _fail(
            "MISSING_EOF_MEMBER",
            "last member is not the canonical 28-byte BGZF EOF block",
            eof_start,
        )

    data_members = members[:-1]
    if not data_members:
        raise _fail(
            "NO_DATA_BLOCKS",
            "archive contains only the EOF member and no data blocks",
            0,
        )
    # Exactly one standard EOF member is allowed: the final one.  An EOF
    # sentinel anywhere in the data region means the archive does not end
    # with exactly one.
    for start, _end, payload in data_members:
        if not payload and archive[start : start + len(EOF_MEMBER)] == EOF_MEMBER:
            raise _fail(
                "UNEXPECTED_EOF_MEMBER",
                "canonical EOF member appears before the end of the archive",
                start,
            )
    if len(data_members) > MAX_DATA_BLOCKS:
        raise _fail(
            "TOO_MANY_BLOCKS",
            f"archive has {len(data_members)} data blocks, limit is {MAX_DATA_BLOCKS}",
            data_members[MAX_DATA_BLOCKS][0],
        )

    _audit_index(index, data_members)

    return AuditedArchive(
        archive=archive,
        blocks=tuple(Block(start, end, payload) for start, end, payload in data_members),
        eof_start=eof_start,
        uncompressed_length=sum(len(payload) for _s, _e, payload in data_members),
    )


def audit(archive: bytes, index: bytes) -> AuditResult:
    """Validate a BGZF archive together with its companion block index."""
    return audit_archive(archive, index).audit_result()


def _audit_index(index: bytes, data_members: list[tuple[int, int, bytes]]) -> None:
    """Check the little-endian offset-pair index against the data blocks."""
    expected = len(data_members) - 1
    header_size = 8
    entry_size = 16
    min_size = header_size + expected * entry_size

    if len(index) < header_size:
        raise AuditError(
            "INDEX_TRUNCATED",
            "index is shorter than its 8-byte count header",
            None,
        )
    (count,) = struct.unpack_from("<Q", index, 0)
    if count != expected:
        raise AuditError(
            "INDEX_COUNT_MISMATCH",
            f"index declares {count} entries, archive has {expected} non-first data blocks",
            None,
        )
    if len(index) != min_size:
        raise AuditError(
            "INDEX_SIZE_MISMATCH",
            f"index for {count} entries must be {min_size} bytes, got {len(index)}",
            None,
        )

    # Cumulative decompressed start of block k = sum of payload lengths of
    # blocks 0..k-1.  The first entry (block 1) starts after block 0.
    cumulative = len(data_members[0][2])
    for i, (comp_off, uncomp_off) in enumerate(
        struct.iter_unpack("<QQ", index[header_size:])
    ):
        member_index = i + 1  # index entries correspond to blocks 1..n-1
        start, _end, payload = data_members[member_index]

        if comp_off != start:
            raise AuditError(
                "INDEX_COMPRESSED_OFFSET_MISMATCH",
                (
                    f"index entry {i}: compressed offset {comp_off} does not "
                    f"match block start {start}"
                ),
                start,
            )
        if uncomp_off != cumulative:
            raise AuditError(
                "INDEX_UNCOMPRESSED_OFFSET_MISMATCH",
                (
                    f"index entry {i}: uncompressed offset {uncomp_off} does not "
                    f"match cumulative payload start {cumulative}"
                ),
                start,
            )
        cumulative += len(payload)


def _make_virtual_offset(compressed_start: int, block_offset: int) -> int:
    return (compressed_start << VIRTUAL_OFFSET_SHIFT) | block_offset


def _split_virtual_offset(value: int) -> tuple[int, int]:
    return value >> VIRTUAL_OFFSET_SHIFT, value & VIRTUAL_OFFSET_MASK


def _resolve_virtual_offset(
    audited: AuditedArchive, value: int, *, allow_eof: bool, side: str
) -> tuple[int, int]:
    """Map a canonical virtual offset to ``(block_index, block_offset)``.

    ``block_index`` may equal ``len(blocks)`` only when ``allow_eof`` is
    set and the offset is exactly the start of the canonical EOF member
    with a zero in-block position.  Any non-canonical or unlocatable
    offset raises :class:`AuditError`.
    """
    compressed_start, block_offset = _split_virtual_offset(value)

    for i, block in enumerate(audited.blocks):
        if block.start == compressed_start:
            payload_len = len(block.payload)
            if block_offset > payload_len:
                raise AuditError(
                    "VIRTUAL_OFFSET_OUT_OF_RANGE",
                    (
                        f"{side} virtual offset {value}: block-internal position "
                        f"{block_offset} exceeds payload length {payload_len} of "
                        f"block starting at {compressed_start}"
                    ),
                    compressed_start,
                )
            if payload_len and block_offset == payload_len:
                # A block's end is canonically named by the next block's
                # start (or by the EOF member start after the last block);
                # encoding it as this block's inner end is ambiguous and
                # therefore not canonical.
                raise AuditError(
                    "VIRTUAL_OFFSET_NOT_CANONICAL",
                    (
                        f"{side} virtual offset {value}: inner position "
                        f"{block_offset} equals the payload length of the block "
                        f"starting at {compressed_start}; name a block boundary "
                        "through the next block's start (or the EOF member start)"
                    ),
                    compressed_start,
                )
            # inner == 0 on a zero-length data block is a legal reader
            # offset that names the same decompressed position as the
            # following block's start.
            return i, block_offset

    # The end point may sit on the start of the EOF member, which marks
    # the end of the audited decompressed stream.
    if allow_eof and compressed_start == audited.eof_start and block_offset == 0:
        return len(audited.blocks), 0

    if compressed_start == audited.eof_start:
        # EOF member reached with a nonzero inner offset, or used as start.
        if not allow_eof:
            raise AuditError(
                "VIRTUAL_OFFSET_NOT_CANONICAL",
                (
                    f"{side} virtual offset {value}: the start endpoint must "
                    "lie within an audited data block, not on the EOF member"
                ),
                audited.eof_start,
            )
        raise AuditError(
            "VIRTUAL_OFFSET_NOT_CANONICAL",
            (
                f"{side} virtual offset {value}: only offset "
                f"{_make_virtual_offset(audited.eof_start, 0)} (the EOF member start) "
                "may reference the EOF member"
            ),
            audited.eof_start,
        )

    raise AuditError(
        "VIRTUAL_OFFSET_NOT_CANONICAL",
        (
            f"{side} virtual offset {value}: compressed start {compressed_start} "
            "is not the start of an audited data block"
        ),
        compressed_start if compressed_start <= len(audited.archive) else None,
    )


def extract(
    archive: bytes, index: bytes, virtual_start: int, virtual_end: int
) -> tuple[bytes, int, int]:
    """Return the audited payload slice ``[virtual_start, virtual_end)``.

    The archive and index are fully re-audited before any byte is sliced,
    so an invalid or unaudited endpoint can never return partial data.
    Returns ``(data, canonical_start, canonical_end)``.  The interval is
    half-open, follows archive order, may be empty and may contain at
    most :data:`MAX_EXTRACT_SIZE` decompressed bytes.
    """
    if not isinstance(virtual_start, int) or isinstance(virtual_start, bool):
        raise AuditError("BAD_VIRTUAL_OFFSET", "virtualStart must be an unsigned 64-bit integer", None)
    if not isinstance(virtual_end, int) or isinstance(virtual_end, bool):
        raise AuditError("BAD_VIRTUAL_OFFSET", "virtualEnd must be an unsigned 64-bit integer", None)
    if not (0 <= virtual_start <= UINT64_MAX) or not (0 <= virtual_end <= UINT64_MAX):
        raise AuditError("BAD_VIRTUAL_OFFSET", "virtual offsets must be unsigned 64-bit integers", None)

    # Audit first: nothing is returned for an archive that fails the
    # existing checks, and endpoints must be backed by audited blocks.
    audited = audit_archive(archive, index)

    start_block, start_off = _resolve_virtual_offset(
        audited, virtual_start, allow_eof=False, side="start"
    )
    end_block, end_off = _resolve_virtual_offset(
        audited, virtual_end, allow_eof=True, side="end"
    )

    # Translate both endpoints onto the linear decompressed stream.  The
    # EOF endpoint (block index == len(blocks)) maps to the stream end.
    uncomp_starts: list[int] = []
    cumulative = 0
    for block in audited.blocks:
        uncomp_starts.append(cumulative)
        cumulative += len(block.payload)

    start_pos = uncomp_starts[start_block] + start_off
    end_pos = (
        audited.uncompressed_length
        if end_block == len(audited.blocks)
        else uncomp_starts[end_block] + end_off
    )

    if start_pos > end_pos:
        raise AuditError(
            "VIRTUAL_OFFSET_REVERSED",
            (
                f"start virtual offset {virtual_start} is after end virtual offset "
                f"{virtual_end} in the decompressed stream"
            ),
            virtual_start >> VIRTUAL_OFFSET_SHIFT,
        )
    length = end_pos - start_pos
    if length > MAX_EXTRACT_SIZE:
        raise AuditError(
            "EXTRACT_TOO_LARGE",
            f"extraction spans {length} bytes, limit is {MAX_EXTRACT_SIZE}",
            virtual_start >> VIRTUAL_OFFSET_SHIFT,
        )

    # Assemble the slice in archive order, touching only blocks the
    # interval covers -- the whole archive is never served.  The block
    # holding the exclusive end point is included; the lo/hi clamping
    # below naturally yields an empty intersection for empty ranges.
    pieces: list[bytes] = []
    last_block = end_block if end_block < len(audited.blocks) else len(audited.blocks) - 1
    for i in range(start_block, last_block + 1):
        block = audited.blocks[i]
        begin = uncomp_starts[i]
        lo = max(start_pos, begin) - begin
        hi = min(end_pos, begin + len(block.payload)) - begin
        if hi > lo:
            pieces.append(block.payload[lo:hi])
    data = b"".join(pieces)

    canonical_start = _make_virtual_offset(
        audited.blocks[start_block].start, start_off
    )
    if end_block == len(audited.blocks):
        canonical_end = _make_virtual_offset(audited.eof_start, 0)
    else:
        canonical_end = _make_virtual_offset(audited.blocks[end_block].start, end_off)
    return data, canonical_start, canonical_end
