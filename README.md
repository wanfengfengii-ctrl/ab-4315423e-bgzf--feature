# BGZF 归档审计服务

基因组归档平台在接收随机访问文件前，用本服务核对 BGZF（Blocked GNU Zip
Format）压缩数据与配套块索引，避免损坏成员或偏移漂移导致后续区间读取落
到错误位置。

纯 Python 标准库实现，无第三方依赖。

## 接口

### `POST /api/bgzf/audit`

`multipart/form-data`：

| 字段 | 内容 |
| --- | --- |
| `archive` | BGZF 压缩归档，不超过 **8 MiB**，最多 **4096** 个数据块 |
| `index` | 配套块索引 |

索引格式（小端无符号 64 位整数）：

```
uint64 count                                  # 非首数据块数量 = 数据块数 - 1
{ uint64 compressed_start;                    # 该块在压缩文件中的起点
  uint64 uncompressed_start; } * count        # 累计解压起点
```

成功响应 `200`：

```json
{
  "data_blocks": 3,
  "uncompressed_length": 1284,
  "sha256": "…"
}
```

其中 `sha256` 是全部数据块解压字节流拼接后的 SHA-256。

### `POST /api/bgzf/extract`

按 BGZF 虚拟偏移从归档中取出精确片段，避免下载整份归档。归档与索引先经
过与审计接口完全相同的校验，任何审计失败都按原错误语义返回，无效端点无
法绕过校验取到未审计数据。

`multipart/form-data`：

| 字段 | 内容 |
| --- | --- |
| `archive` | BGZF 压缩归档，不超过 **8 MiB**，最多 **4096** 个数据块 |
| `index` | 配套块索引 |
| `virtualStart` | 十进制无符号 64 位虚拟偏移（区间起点，含） |
| `virtualEnd` | 十进制无符号 64 位虚拟偏移（区间终点，不含） |

虚拟偏移布局：**高 48 位为成员压缩起点，低 16 位为块内解压位置**。端点
必须规范且落在已审计数据块上：

- 高 48 位必须是某个数据块的压缩起点（不得落在成员中间或归档之外）；
- 低 16 位必须严格小于该块解压长度（等于块长的位置应写成下一块起点）；
- 终点还可为 EOF 成员起点（块内偏移为 0），表示数据末尾；起点不可以。

区间左闭右开、允许为空（起点等于终点时返回 0 字节）。跨块片段按归档顺
序拼接，结果最大 **1 MiB**。

成功响应 `200`，正文为 `application/octet-stream` 原始字节，并带响应头：

| 响应头 | 内容 |
| --- | --- |
| `Content-Length` | 片段精确长度 |
| `X-Bgzf-Virtual-Start` / `X-Bgzf-Virtual-End` | 规范端点（十进制） |
| `X-Bgzf-Sha256` | 片段内容的 SHA-256（十六进制） |

端点非法、逆序或结果超限时返回 `422` 与稳定错误码，绝不返回部分字节。

### 校验规则

- 每个成员必须有合法 gzip 头（magic `1f 8b`、CM=deflate）且**恰好一个**
  `BC` 子字段（重复即拒绝）；
- `BSIZE` 声明块长必须与成员边界一致，raw-deflate 流必须恰好在 gzip
  trailer 前终止（不短、不长，不允许夹带字节）；
- trailer 中 CRC32 与 ISIZE 必须与解压数据一致；
- 归档末尾必须**恰有一个**标准的 28 字节 BGZF EOF 成员
  （`1f8b08040000000000ff0600424302001b0003000000000000000000`），其后
  不得附加任何字节；数据区中也不得出现该标准 EOF 成员；
- 索引项必须逐项对应每个非首数据块的压缩起点与累计解压起点。

### 错误响应

任何格式、校验或索引不一致都返回 `422`（归档超过 8 MiB 返回 `413`），
且绝不返回部分结果：

```json
{
  "error": {
    "code": "CRC32_MISMATCH",
    "message": "stored CRC32 deadbeef does not match payload …",
    "offset": 26
  }
}
```

`offset` 是**首个可定位的压缩偏移**（归档字节位置），归档人员可据此判
断应重传数据（数据块损坏：`BAD_MAGIC`、`BAD_DEFLATE`、
`CRC32_MISMATCH`、`ISIZE_MISMATCH`、`DEFLATE_*` 等）还是重建索引
（`INDEX_*`）。纯索引头部问题（如计数不符）无法定位到压缩偏移时
`offset` 为 `null`。

稳定错误码：

| 代码 | 含义 |
| --- | --- |
| `EMPTY_ARCHIVE` | 归档为空 |
| `BAD_MAGIC` / `TRUNCATED_HEADER` | 成员头损坏或截断 |
| `BAD_COMPRESSION_METHOD` / `UNSUPPORTED_HEADER_FLAGS` | 非 BGZF gzip 成员 |
| `MISSING_BC_FIELD` / `DUPLICATE_BC_FIELD` / `BAD_BC_FIELD` | BC 子字段缺失、重复或非法 |
| `BAD_EXTRA_FIELD` | FEXTRA 结构损坏 |
| `BAD_BLOCK_SIZE` / `BLOCK_SIZE_OVERRUN` | 声明块长非法或超出归档 |
| `BAD_DEFLATE` / `DEFLATE_NOT_TERMINATED` / `DEFLATE_BOUNDARY_MISMATCH` | Deflate 流损坏或边界漂移 |
| `CRC32_MISMATCH` / `ISIZE_MISMATCH` | 校验和 / 解压长度不符 |
| `MISSING_EOF_MEMBER` / `UNEXPECTED_EOF_MEMBER` | 末尾标准 EOF 缺失或数据区提前出现 EOF |
| `TOO_MANY_BLOCKS` | 数据块超过 4096 |
| `INDEX_TRUNCATED` / `INDEX_COUNT_MISMATCH` / `INDEX_SIZE_MISMATCH` | 索引结构错误 |
| `INDEX_COMPRESSED_OFFSET_MISMATCH` / `INDEX_UNCOMPRESSED_OFFSET_MISMATCH` | 索引偏移漂移（重建索引） |
| `BAD_VIRTUAL_OFFSET` | 虚拟偏移不是十进制无符号 64 位整数 |
| `VIRTUAL_OFFSET_NOT_BLOCK_START` | 虚拟偏移高 48 位不是任何成员的压缩起点 |
| `VIRTUAL_OFFSET_NOT_CANONICAL` | 端点不规范（块内偏移越界、EOF 被用作起点等） |
| `VIRTUAL_OFFSETS_REVERSED` | 提取起点在终点之后 |
| `EXTRACT_TOO_LARGE` | 提取区间超过 1 MiB |
| `ARCHIVE_TOO_LARGE` / `REQUEST_TOO_LARGE` | 超过大小限制（HTTP 413） |
| `MALFORMED_MULTIPART` / `MISSING_PART` | 请求格式错误 |

### `GET /healthz`

健康检查端点，正常返回 `200 {"status":"ok"}`。

## 运行

```bash
# 启动服务（主机端口可用 HOST_PORT 覆盖，容器内监听端口用 PORT）
HOST_PORT=8080 docker compose up -d app

# 一次性验证服务：等待健康后执行构建检查、测试与冒烟样例
# （run 会先构建镜像并按 depends_on 等待 app 健康）
docker compose run --rm --build verify
```

verify 服务依次执行：

1. 等待 `/healthz` 健康；
2. 构建检查（`compileall`）；
3. 单元与 HTTP 端到端测试（`unittest`）；
4. 提交审计冒烟样例：合法归档、CRC32 损坏、声明块长漂移、索引错位，
   后三者必须返回带稳定错误码与压缩偏移的 `422`；
5. 提交提取冒烟样例：单块、跨块（核对字节与响应头摘要）、非法端点、
   超限提取（必须 `422` 且不返回部分字节）。

全部通过以退出码 `0` 结束，否则退出码为 `1`。

## 本地开发

```bash
python -m unittest discover -s tests -v
PORT=8080 python -m app.server
```
