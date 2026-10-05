"""End-to-end HTTP tests against a real server socket."""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import struct
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.bgzf import MAX_EXTRACT_SIZE  # noqa: E402
from app.server import create_server  # noqa: E402
from tests.bgzf_fixtures import bgzf_block, build_archive, build_index, encode_multipart  # noqa: E402


def vo(compressed_start: int, block_offset: int = 0) -> int:
    return (compressed_start << 16) | block_offset


class HttpServerTestBase(unittest.TestCase):
    def setUp(self):
        self.server = create_server(host="127.0.0.1", port=0)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()

    def post_audit(self, fields, content_type=None, raw_body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        if raw_body is not None:
            conn.request("POST", "/api/bgzf/audit", body=raw_body, headers={"Content-Type": content_type})
        else:
            body, ct = encode_multipart(fields)
            conn.request(
                "POST",
                "/api/bgzf/audit",
                body=body,
                headers={"Content-Type": ct, "Content-Length": str(len(body))},
            )
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, json.loads(data) if data else None

    def get(self, path):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("GET", path)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, json.loads(data)


class AuditEndpointTests(HttpServerTestBase):
    def test_healthz(self):
        status, body = self.get("/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "ok")

    def test_valid_archive_ok(self):
        payloads = [b"block-zero", b"block-one", b"block-two"]
        archive = build_archive(payloads)
        index = build_index(archive, payloads)
        status, body = self.post_audit(
            {"archive": ("a.bgz", archive), "index": ("a.gzi", index)}
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(body["data_blocks"], 3)
        self.assertEqual(body["uncompressed_length"], sum(map(len, payloads)))

    def test_crc_corruption_returns_422_with_offset(self):
        payloads = [b"aaaa", b"bbbb"]
        archive = bytearray(build_archive(payloads))
        block0_len = len(bgzf_block(b"aaaa"))
        struct.pack_into("<I", archive, block0_len - 8, 0x0BADF00D)
        index = build_index(bytes(archive), payloads)
        status, body = self.post_audit(
            {"archive": ("a.bgz", bytes(archive)), "index": ("a.gzi", index)}
        )
        self.assertEqual(status, 422)
        self.assertEqual(body["error"]["code"], "CRC32_MISMATCH")
        self.assertEqual(body["error"]["offset"], block0_len - 8)

    def test_block_size_drift_returns_422_with_offset(self):
        payloads = [b"aaaa", b"bbbb"]
        archive = bytearray(build_archive(payloads))
        struct.pack_into("<H", archive, 16, struct.unpack_from("<H", archive, 16)[0] - 1)
        index = build_index(bytes(archive), payloads)
        status, body = self.post_audit(
            {"archive": ("a.bgz", bytes(archive)), "index": ("a.gzi", index)}
        )
        self.assertEqual(status, 422)
        self.assertIn(
            body["error"]["code"],
            {"DEFLATE_NOT_TERMINATED", "BAD_BLOCK_SIZE", "CRC32_MISMATCH"},
        )
        self.assertIsNotNone(body["error"]["offset"])

    def test_index_drift_returns_422(self):
        payloads = [b"aaaa", b"bbbb"]
        archive = build_archive(payloads)
        index = bytearray(build_index(archive, payloads))
        struct.pack_into("<Q", index, 8, 0)  # compressed offset of block 1 wrong
        status, body = self.post_audit(
            {"archive": ("a.bgz", archive), "index": ("a.gzi", bytes(index))}
        )
        self.assertEqual(status, 422)
        self.assertEqual(body["error"]["code"], "INDEX_COMPRESSED_OFFSET_MISMATCH")
        self.assertEqual(body["error"]["offset"], len(bgzf_block(b"aaaa")))

    def test_missing_part(self):
        payloads = [b"aaaa"]
        archive = build_archive(payloads)
        status, body = self.post_audit({"archive": ("a.bgz", archive)})
        self.assertEqual(status, 422)
        self.assertEqual(body["error"]["code"], "MISSING_PART")

    def test_wrong_content_type(self):
        status, body = self.post_audit(
            {}, content_type="application/json", raw_body=b"{}"
        )
        self.assertEqual(status, 415)
        self.assertEqual(body["error"]["code"], "UNSUPPORTED_MEDIA_TYPE")

    def test_not_found(self):
        status, body = self.get("/nope")
        self.assertEqual(status, 404)
        self.assertEqual(body["error"]["code"], "NOT_FOUND")

    def test_error_shape_is_stable(self):
        # Garbage archive must not leak a partial result; exactly one error
        # object with code/message/offset is returned.
        body_bytes, ct = encode_multipart(
            {"archive": ("a.bgz", b"garbage"), "index": ("a.gzi", struct.pack("<Q", 0))}
        )
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("POST", "/api/bgzf/audit", body=body_bytes, headers={"Content-Type": ct})
        resp = conn.getresponse()
        payload = json.loads(resp.read())
        conn.close()
        self.assertEqual(resp.status, 422)
        self.assertEqual(set(payload.keys()), {"error"})
        self.assertEqual(set(payload["error"].keys()), {"code", "message", "offset"})
        self.assertEqual(payload["error"]["code"], "BAD_MAGIC")
        self.assertEqual(payload["error"]["offset"], 0)


class ExtractEndpointTests(HttpServerTestBase):
    def setUp(self):
        super().setUp()
        self.payloads = [b"block-zero", b"block-one!!", b"block-two"]
        self.archive = build_archive(self.payloads)
        self.index = build_index(self.archive, self.payloads)
        sizes = [len(bgzf_block(p)) for p in self.payloads]
        self.starts = [0, sizes[0], sizes[0] + sizes[1]]
        self.eof_start = self.starts[2] + sizes[2]

    def post_extract(self, virtual_start, virtual_end, archive=None, index=None):
        fields = {
            "archive": ("a.bgz", self.archive if archive is None else archive),
            "index": ("a.gzi", self.index if index is None else index),
            "virtualStart": ("start", str(virtual_start).encode()),
            "virtualEnd": ("end", str(virtual_end).encode()),
        }
        body, ct = encode_multipart(fields)
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request(
            "POST",
            "/api/bgzf/extract",
            body=body,
            headers={"Content-Type": ct, "Content-Length": str(len(body))},
        )
        resp = conn.getresponse()
        data = resp.read()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        conn.close()
        return resp.status, headers, data

    def test_single_block_extract(self):
        status, headers, data = self.post_extract(
            vo(self.starts[0], 3), vo(self.starts[0], 8)
        )
        self.assertEqual(status, 200, data)
        self.assertEqual(data, b"ck-ze")
        self.assertEqual(headers["content-type"], "application/octet-stream")
        self.assertEqual(int(headers["content-length"]), len(data))
        self.assertEqual(headers["x-virtual-start"], str(vo(self.starts[0], 3)))
        self.assertEqual(headers["x-virtual-end"], str(vo(self.starts[0], 8)))
        self.assertEqual(headers["x-content-sha256"], hashlib.sha256(data).hexdigest())

    def test_cross_block_extract_is_concatenated_in_order(self):
        status, headers, data = self.post_extract(
            vo(self.starts[0], 6), vo(self.starts[2], 5)
        )
        self.assertEqual(status, 200, data)
        self.assertEqual(data, b"zero" + b"block-one!!" + b"block")
        self.assertEqual(int(headers["content-length"]), len(data))
        self.assertEqual(headers["x-content-sha256"], hashlib.sha256(data).hexdigest())

    def test_extract_to_eof_start_and_empty_interval(self):
        status, headers, data = self.post_extract(
            vo(self.starts[2], 6), vo(self.eof_start)
        )
        self.assertEqual(status, 200)
        self.assertEqual(data, b"two")
        self.assertEqual(headers["x-virtual-end"], str(vo(self.eof_start)))

        status, headers, data = self.post_extract(
            vo(self.starts[1], 2), vo(self.starts[1], 2)
        )
        self.assertEqual(status, 200)
        self.assertEqual(data, b"")
        self.assertEqual(headers["content-length"], "0")

    def test_illegal_endpoint_returns_422_and_no_bytes(self):
        for bad_start, bad_end in (
            (vo(self.starts[0], 99), vo(self.eof_start)),
            (vo(5), vo(self.eof_start)),
            (vo(self.eof_start), vo(self.eof_start)),
            (vo(self.starts[0]), vo(self.starts[0], 10)),
        ):
            status, headers, data = self.post_extract(bad_start, bad_end)
            self.assertEqual(status, 422, (bad_start, bad_end, data))
            self.assertEqual(headers["content-type"], "application/json")
            body = json.loads(data)
            self.assertIn(body["error"]["code"],
                          {"VIRTUAL_OFFSET_NOT_CANONICAL", "VIRTUAL_OFFSET_OUT_OF_RANGE"})
            self.assertEqual(set(body["error"].keys()), {"code", "message", "offset"})

    def test_reversed_interval_returns_422(self):
        status, _headers, data = self.post_extract(
            vo(self.starts[2], 1), vo(self.starts[1], 1)
        )
        self.assertEqual(status, 422)
        self.assertEqual(json.loads(data)["error"]["code"], "VIRTUAL_OFFSET_REVERSED")

    def test_malformed_offset_returns_422(self):
        fields = {
            "archive": ("a.bgz", self.archive),
            "index": ("a.gzi", self.index),
            "virtualStart": ("start", b"-1"),
            "virtualEnd": ("end", b"0"),
        }
        body, ct = encode_multipart(fields)
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("POST", "/api/bgzf/extract", body=body, headers={"Content-Type": ct})
        resp = conn.getresponse()
        payload = json.loads(resp.read())
        conn.close()
        self.assertEqual(resp.status, 422)
        self.assertEqual(payload["error"]["code"], "BAD_VIRTUAL_OFFSET")

        fields["virtualStart"] = ("start", str(2**64).encode())
        body, ct = encode_multipart(fields)
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("POST", "/api/bgzf/extract", body=body, headers={"Content-Type": ct})
        resp = conn.getresponse()
        payload = json.loads(resp.read())
        conn.close()
        self.assertEqual(resp.status, 422)
        self.assertEqual(payload["error"]["code"], "BAD_VIRTUAL_OFFSET")

    def test_over_limit_returns_422(self):
        payloads = [b"\0" * 60000 for _ in range(20)]
        archive = build_archive(payloads)
        index = build_index(archive, payloads)
        sizes = [len(bgzf_block(p)) for p in payloads]
        starts = [0]
        for size in sizes[:-1]:
            starts.append(starts[-1] + size)
        eof_start = starts[-1] + sizes[-1]
        status, headers, data = self.post_extract(
            vo(0), vo(eof_start), archive=archive, index=index
        )
        self.assertEqual(status, 422)
        body = json.loads(data)
        self.assertEqual(body["error"]["code"], "EXTRACT_TOO_LARGE")
        self.assertEqual(headers["content-type"], "application/json")

    def test_corrupt_archive_is_rejected_without_bytes(self):
        block0_len = len(bgzf_block(self.payloads[0]))
        broken = bytearray(self.archive)
        struct.pack_into("<I", broken, block0_len - 8, 0xDEADBEEF)
        status, _headers, data = self.post_extract(
            vo(0), vo(self.eof_start), archive=bytes(broken)
        )
        self.assertEqual(status, 422)
        self.assertEqual(json.loads(data)["error"]["code"], "CRC32_MISMATCH")

    def test_missing_extract_parts(self):
        fields = {
            "archive": ("a.bgz", self.archive),
            "index": ("a.gzi", self.index),
            "virtualStart": ("start", b"0"),
        }
        body, ct = encode_multipart(fields)
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("POST", "/api/bgzf/extract", body=body, headers={"Content-Type": ct})
        resp = conn.getresponse()
        body_obj = json.loads(resp.read())
        conn.close()
        self.assertEqual(resp.status, 422)
        self.assertEqual(body_obj["error"]["code"], "MISSING_PART")

    def test_exactly_limit_succeeds(self):
        payloads = [b"\0" * 60000 for _ in range(20)]
        archive = build_archive(payloads)
        index = build_index(archive, payloads)
        sizes = [len(bgzf_block(p)) for p in payloads]
        starts = [0]
        for size in sizes[:-1]:
            starts.append(starts[-1] + size)
        end_inner = MAX_EXTRACT_SIZE - 17 * 60000
        status, headers, data = self.post_extract(
            vo(0), vo(starts[17], end_inner), archive=archive, index=index
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(data), MAX_EXTRACT_SIZE)


if __name__ == "__main__":
    unittest.main(verbosity=2)
