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

from app.server import create_server  # noqa: E402
from tests.bgzf_fixtures import EOF_MEMBER, bgzf_block, build_archive, build_index, encode_multipart  # noqa: E402


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
    payloads = [b"alpha-alpha", b"beta-beta", b"gamma!"]

    def setUp(self):
        super().setUp()
        self.archive = build_archive(self.payloads)
        self.index = build_index(self.archive, self.payloads)
        self.starts: list[int] = []
        pos = 0
        for payload in self.payloads:
            self.starts.append(pos)
            pos += len(bgzf_block(payload))
        self.eof_start = pos

    def extract_fields(self, virtual_start, virtual_end, archive=None, index=None):
        return {
            "archive": ("a.bgz", self.archive if archive is None else archive),
            "index": ("a.gzi", self.index if index is None else index),
            "virtualStart": ("", str(virtual_start).encode()),
            "virtualEnd": ("", str(virtual_end).encode()),
        }

    def post_extract(self, fields):
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
        headers = {name.lower(): value for name, value in resp.getheaders()}
        conn.close()
        return resp.status, headers, data

    def test_single_block_extract(self):
        vs = (self.starts[1] << 16) | 2
        ve = (self.starts[1] << 16) | 7
        status, headers, data = self.post_extract(self.extract_fields(vs, ve))
        self.assertEqual(status, 200, data)
        self.assertEqual(headers["content-type"], "application/octet-stream")
        self.assertEqual(data, self.payloads[1][2:7])
        self.assertEqual(int(headers["content-length"]), len(data))
        self.assertEqual(headers["x-bgzf-virtual-start"], str(vs))
        self.assertEqual(headers["x-bgzf-virtual-end"], str(ve))
        self.assertEqual(headers["x-bgzf-sha256"], hashlib.sha256(data).hexdigest())

    def test_cross_block_extract(self):
        vs = (self.starts[0] << 16) | 5
        ve = (self.starts[2] << 16) | 2
        expected = self.payloads[0][5:] + self.payloads[1] + self.payloads[2][:2]
        status, headers, data = self.post_extract(self.extract_fields(vs, ve))
        self.assertEqual(status, 200, data)
        self.assertEqual(data, expected)
        self.assertEqual(headers["x-bgzf-sha256"], hashlib.sha256(expected).hexdigest())

    def test_extract_to_eof_start(self):
        status, headers, data = self.post_extract(
            self.extract_fields(0, self.eof_start << 16)
        )
        self.assertEqual(status, 200, data)
        self.assertEqual(data, b"".join(self.payloads))

    def test_empty_range(self):
        point = (self.starts[0] << 16) | 3
        status, headers, data = self.post_extract(self.extract_fields(point, point))
        self.assertEqual(status, 200, data)
        self.assertEqual(data, b"")
        self.assertEqual(headers["content-length"], "0")

    def test_endpoint_not_on_block_start(self):
        status, _headers, data = self.post_extract(
            self.extract_fields(3 << 16, self.eof_start << 16)
        )
        self.assertEqual(status, 422)
        self.assertEqual(json.loads(data)["error"]["code"], "VIRTUAL_OFFSET_NOT_BLOCK_START")

    def test_non_canonical_endpoint(self):
        # inner offset == payload length must be normalized to the next
        # block's start; the raw form is rejected.
        vs = len(self.payloads[0])
        status, _headers, data = self.post_extract(
            self.extract_fields(vs, self.eof_start << 16)
        )
        self.assertEqual(status, 422)
        self.assertEqual(json.loads(data)["error"]["code"], "VIRTUAL_OFFSET_NOT_CANONICAL")

    def test_reversed_range(self):
        vs = self.starts[2] << 16
        ve = self.starts[1] << 16
        status, _headers, data = self.post_extract(self.extract_fields(vs, ve))
        self.assertEqual(status, 422)
        self.assertEqual(json.loads(data)["error"]["code"], "VIRTUAL_OFFSETS_REVERSED")

    def test_bad_offset_string(self):
        status, _headers, data = self.post_extract(
            self.extract_fields("not-a-number", self.eof_start << 16)
        )
        self.assertEqual(status, 422)
        self.assertEqual(json.loads(data)["error"]["code"], "BAD_VIRTUAL_OFFSET")

    def test_missing_offset_part(self):
        fields = self.extract_fields(0, self.eof_start << 16)
        del fields["virtualStart"]
        status, _headers, data = self.post_extract(fields)
        self.assertEqual(status, 422)
        self.assertEqual(json.loads(data)["error"]["code"], "MISSING_PART")

    def test_corrupt_archive_is_not_bypassed(self):
        broken = bytearray(self.archive)
        struct.pack_into("<I", broken, len(bgzf_block(self.payloads[0])) - 8, 0x0BADF00D)
        status, _headers, data = self.post_extract(
            self.extract_fields(0, self.eof_start << 16, archive=bytes(broken))
        )
        self.assertEqual(status, 422)
        self.assertEqual(json.loads(data)["error"]["code"], "CRC32_MISMATCH")

    def test_over_limit_extract_returns_no_partial_bytes(self):
        payloads = [b"y" * 65536] * 17  # 17 * 64 KiB > 1 MiB
        archive = build_archive(payloads)
        index = build_index(archive, payloads)
        eof = len(archive) - len(EOF_MEMBER)
        status, _headers, data = self.post_extract(
            self.extract_fields(0, eof << 16, archive=archive, index=index)
        )
        self.assertEqual(status, 422)
        payload = json.loads(data)
        self.assertEqual(set(payload.keys()), {"error"})
        self.assertEqual(payload["error"]["code"], "EXTRACT_TOO_LARGE")


if __name__ == "__main__":
    unittest.main(verbosity=2)
