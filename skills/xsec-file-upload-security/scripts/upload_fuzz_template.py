#!/usr/bin/env python3
"""
Safe full-strategy file-upload fuzz template for testing.

This script adapts the strategy set from Upload_Auto_Fuzz
(https://github.com/T3nk0/Upload_Auto_Fuzz) into regular Python:
- no Burp/Jython dependency
- no GUI
- no webshell payloads
- config-file probes use harmless marker content instead of parser-changing rules

By default the script generates raw HTTP upload requests and does not send
anything. Use --send explicitly in the isolated xSec environment; naturally
discovered targets are not filtered by the initial scope.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import hashlib
import http.client
import json
import re
import ssl
import sys
import time
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts"))
from xsec_paths import resolve_artifact_path, resolve_output_path


MARKER = b"xsec-upload-check"
MAX_FILENAME_LENGTH = 255
MAX_PAYLOADS_DEFAULT = 2000

BACKEND_LANGUAGES = {
    "php": ["php", "php3", "php4", "php5", "php7", "php8", "phtml", "pht", "phpt", "phar", "pgif"],
    "asp": ["asp", "asa", "cer", "cdx", "htr"],
    "aspx": ["aspx", "ashx", "asmx", "asax"],
    "jsp": ["jsp", "jspa", "jsps", "jspx", "jspf"],
}

IMAGE_MIME_TYPES = [
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/bmp",
    "image/webp",
    "image/svg+xml",
    "image/tiff",
]

MAGIC_BYTES = {
    "jpg": b"\xff\xd8\xff\xe0",
    "png": b"\x89PNG\r\n\x1a\n",
    "gif": b"GIF89a",
    "gif87": b"GIF87a",
    "bmp": b"BM",
    "pdf": b"%PDF-1.5",
    "zip": b"PK\x03\x04",
}

JPEG_BYTES = (
    b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    + MARKER
    + b"\xff\xd9"
)
SVG_BYTES = b'<svg xmlns="http://www.w3.org/2000/svg"><desc>xsec-upload-check</desc></svg>'
TEXT_BYTES = b"xsec-upload-check\n"

SAFE_CONFIG_CONTENTS = {
    ".htaccess": b"# xsec-upload-check\n",
    ".user.ini": b"; xsec-upload-check\n",
    "web.config": b"<configuration><!-- xsec-upload-check --></configuration>\n",
    ".php.ini": b"; xsec-upload-check\n",
    "php.ini": b"; xsec-upload-check\n",
}

SAMPLE_RAW_REQUEST = b"""POST /upload HTTP/1.1
Host: example.test
User-Agent: xsec-upload-template
Content-Type: multipart/form-data; boundary=----xsecUploadBoundary
Content-Length: 177

------xsecUploadBoundary
Content-Disposition: form-data; name="file"; filename="test.jpg"
Content-Type: image/jpeg

xsec-upload-check
------xsecUploadBoundary--
"""


SUFFIX_BYPASS_PATTERNS = {
    "php": [
        "php3",
        "php4",
        "php5",
        "php7",
        "php8",
        "phtml",
        "pht",
        "phar",
        "phps",
        "php1",
        "php2",
        "pgif",
        "pHp",
        "PhP",
        "PHP",
        "pHP",
        "PHp",
        "phP",
        "pphphp",
        "phphpp",
        "pphp",
        "php%00",
        "php%00.jpg",
        "php\x00.jpg",
        "php.jpg",
        "php.png",
        "php.gif",
        "jpg.php",
        "png.php",
        "php ",
        "php.",
        "php..",
        "php::$DATA",
        "php:$DATA",
        "php;.jpg",
        "php;jpg",
        "php;.png",
        "php/.jpg",
        "php\\.jpg",
        "p%68p",
        "%70hp",
        "ph%70",
        "p;hp",
        "p hp",
        "ph p",
        "p.hp",
    ],
    "asp": [
        "asa",
        "cer",
        "cdx",
        "htr",
        "asp ",
        "asp.",
        "asp;.jpg",
        "asp;jpg",
        "asp%00",
        "asp%00.jpg",
        "asp::$DATA",
        "aSp",
        "AsP",
        "ASP",
        "aSP",
        "Asp",
        "aspasp",
        "aasps",
        "aspas",
        "a;sp",
        "as p",
        "a.sp",
    ],
    "aspx": [
        "ashx",
        "asmx",
        "asax",
        "ascx",
        "soap",
        "rem",
        "axd",
        "aspx ",
        "aspx.",
        "aspx;.jpg",
        "aSpX",
        "ASPX",
        "AsPx",
        "ASpx",
        "aspX",
        "aspxaspx",
        "aaspxspx",
    ],
    "jsp": [
        "jspa",
        "jsps",
        "jspx",
        "jspf",
        "jsw",
        "jsv",
        "jtml",
        "jsp ",
        "jsp.",
        "jsp;.jpg",
        "jSp",
        "JsP",
        "JSP",
        "jSP",
        "Jsp",
        "jsp%00",
        "jsp%00.jpg",
        "jspjsp",
        "jjsps",
    ],
}

CONTENT_TYPE_MIME_TYPES = [
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/bmp",
    "image/webp",
    "image/svg+xml",
    "image/tiff",
    "text/plain",
    "text/html",
    "application/octet-stream",
    "application/x-httpd-php",
    "application/x-php",
    "application/x-asp",
    "multipart/form-data",
    "image/php",
    "image/asp",
    "image/aspx",
    "image/jsp",
]

NULL_VARIANTS = ["%00", "\\0", "\\x00", "\x00", "%2500", "%u0000"]
WINDOWS_RESERVED_NAMES = ["con", "aux", "nul", "prn", "com1", "com2", "lpt1", "lpt2"]
CONFIG_FILES = [".htaccess", ".user.ini", "web.config", ".php.ini", "php.ini"]
SPECIAL_CHARS = [" ", "\t", "\n", "\r", "/", "\\", ":", "*", "?", '"', "<", ">", "|", ";", "&", "$", "`", "'", "#", "@", "!", "^"]
DOUBLE_ALLOWED_EXTENSIONS = ["jpg", "jpeg", "png", "gif", "bmp", "txt", "pdf", "doc"]


@dataclasses.dataclass(frozen=True)
class RawRequest:
    method: str
    target: str
    version: str
    headers: list[tuple[str, str]]
    body: bytes


@dataclasses.dataclass(frozen=True)
class FuzzCase:
    case_id: str
    category: str
    filename: str
    content_type: str
    file_content: bytes
    reason: str
    filename_token: str | None = None
    remove_part_content_type: bool = False
    content_type_line_template: str = "Content-Type: {content_type}"
    prefix_content_disposition_lines: tuple[str, ...] = ()
    prefix_content_type_lines: tuple[str, ...] = ()
    part_header_replacements: tuple[tuple[str, str], ...] = ()


def _decode_header(value: bytes) -> str:
    return value.decode("latin-1", errors="replace")


def _encode_header(value: str) -> bytes:
    return value.encode("latin-1", errors="replace")


def parse_raw_request(raw: bytes) -> RawRequest:
    separator = b"\r\n\r\n" if b"\r\n\r\n" in raw else b"\n\n"
    if separator not in raw:
        raise ValueError("raw request must contain headers and body separated by a blank line")

    header_bytes, body = raw.split(separator, 1)
    lines = _decode_header(header_bytes).replace("\r\n", "\n").split("\n")
    if not lines or len(lines[0].split()) < 3:
        raise ValueError("raw request must start with: METHOD path HTTP/version")

    method, target, version = lines[0].split(None, 2)
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line.strip() or ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers.append((name.strip(), value.strip()))

    return RawRequest(method=method, target=target, version=version, headers=headers, body=body)


def _headers_without_content_length(headers: Iterable[tuple[str, str]]) -> list[tuple[str, str]]:
    return [(name, value) for name, value in headers if name.lower() != "content-length"]


def render_raw_request(request: RawRequest, body: bytes) -> bytes:
    header_lines = [f"{request.method} {request.target} {request.version}"]
    headers = _headers_without_content_length(request.headers)
    headers.append(("Content-Length", str(len(body))))
    header_lines.extend(f"{name}: {value}" for name, value in headers)
    return _encode_header("\r\n".join(header_lines) + "\r\n\r\n") + body


def get_header(request: RawRequest, header_name: str) -> str | None:
    for name, value in request.headers:
        if name.lower() == header_name.lower():
            return value
    return None


def _newline(body: bytes) -> bytes:
    return b"\r\n" if b"\r\n" in body else b"\n"


def _filename_match(body: bytes) -> re.Match[bytes]:
    match = re.search(br'filename=(?:"[^"]*"|\'[^\']*\'|[^;\r\n]+)', body, flags=re.IGNORECASE)
    if not match:
        raise ValueError("upload body must contain a multipart filename= field")
    return match


def _file_part_header_bounds(body: bytes) -> tuple[int, int]:
    filename_match = _filename_match(body)
    cd_start = body.rfind(b"Content-Disposition", 0, filename_match.start() + 1)
    if cd_start == -1:
        cd_start = filename_match.start()

    header_end_match = re.search(br"\r?\n\r?\n", body[cd_start:])
    if not header_end_match:
        raise ValueError("multipart file part must have a blank line before file content")
    return cd_start, cd_start + header_end_match.start()


def extract_original_filename(body: bytes) -> str:
    token = _filename_match(body).group(0)
    raw_value = token.split(b"=", 1)[1].strip()
    if (raw_value.startswith(b'"') and raw_value.endswith(b'"')) or (
        raw_value.startswith(b"'") and raw_value.endswith(b"'")
    ):
        raw_value = raw_value[1:-1]
    return _decode_header(raw_value)


def extract_part_content_type(body: bytes) -> str:
    start, end = _file_part_header_bounds(body)
    header_slice = body[start:end]
    match = re.search(br"Content-Type:\s*([^\r\n]+)", header_slice, flags=re.IGNORECASE)
    return _decode_header(match.group(1).strip()) if match else "application/octet-stream"


def replace_filename(body: bytes, filename: str, filename_token: str | None = None) -> bytes:
    match = _filename_match(body)
    if filename_token is not None:
        replacement = _encode_header(filename_token)
    else:
        replacement = b'filename="' + _encode_header(filename) + b'"'
    return body[: match.start()] + replacement + body[match.end() :]


def _line_end(body: bytes, index: int) -> int:
    crlf = body.find(b"\r\n", index)
    lf = body.find(b"\n", index)
    candidates = [pos for pos in (crlf, lf) if pos != -1]
    return min(candidates) if candidates else len(body)


def _line_bounds_at(body: bytes, start: int) -> tuple[int, int]:
    end = _line_end(body, start)
    next_start = end + (2 if body[end : end + 2] == b"\r\n" else 1 if end < len(body) else 0)
    return start, next_start


def _replace_file_part_headers(body: bytes, old: bytes, new: bytes) -> bytes:
    start, end = _file_part_header_bounds(body)
    header_slice = body[start:end].replace(old, new)
    return body[:start] + header_slice + body[end:]


def _insert_before_content_disposition(body: bytes, lines: tuple[str, ...]) -> bytes:
    if not lines:
        return body
    start, _ = _file_part_header_bounds(body)
    joiner = _newline(body)
    insertion = joiner.join(_encode_header(line) for line in lines) + joiner
    return body[:start] + insertion + body[start:]


def _insert_before_part_content_type(body: bytes, lines: tuple[str, ...]) -> bytes:
    if not lines:
        return body
    start, end = _file_part_header_bounds(body)
    header_slice = body[start:end]
    ct_match = re.search(br"Content-Type:\s*[^\r\n]*", header_slice, flags=re.IGNORECASE)
    insert_at = start + ct_match.start() if ct_match else _line_end(body, start)
    joiner = _newline(body)
    insertion = joiner.join(_encode_header(line) for line in lines) + joiner
    return body[:insert_at] + insertion + body[insert_at:]


def replace_part_content_type(body: bytes, fuzz_case: FuzzCase) -> bytes:
    start, end = _file_part_header_bounds(body)
    header_slice = body[start:end]
    ct_match = re.search(br"Content-Type:\s*[^\r\n]*", header_slice, flags=re.IGNORECASE)

    if fuzz_case.remove_part_content_type:
        if not ct_match:
            return body
        line_start = start + ct_match.start()
        _, line_end = _line_bounds_at(body, line_start)
        return body[:line_start] + body[line_end:]

    replacement = _encode_header(fuzz_case.content_type_line_template.format(content_type=fuzz_case.content_type))
    if ct_match:
        line_start = start + ct_match.start()
        line_end = start + ct_match.end()
        return body[:line_start] + replacement + body[line_end:]

    filename_match = _filename_match(body)
    insert_at = _line_end(body, filename_match.end())
    joiner = _newline(body)
    return body[:insert_at] + joiner + replacement + body[insert_at:]


def _body_boundary(body: bytes) -> bytes | None:
    first_line = body.splitlines()[0] if body.splitlines() else b""
    if first_line.startswith(b"--") and len(first_line) > 2:
        return first_line[2:]
    return None


def file_content_bounds(body: bytes) -> tuple[int, int]:
    start, _ = _file_part_header_bounds(body)
    header_end_match = re.search(br"\r?\n\r?\n", body[start:])
    if not header_end_match:
        raise ValueError("multipart file part must have a blank line before file content")

    content_start = start + header_end_match.end()
    boundary = _body_boundary(body)
    if not boundary:
        return content_start, len(body)

    candidates = [
        pos
        for pos in (
            body.find(b"\r\n--" + boundary, content_start),
            body.find(b"\n--" + boundary, content_start),
        )
        if pos != -1
    ]
    content_end = min(candidates) if candidates else len(body)
    return content_start, content_end


def replace_file_content(body: bytes, content: bytes) -> bytes:
    start, end = file_content_bounds(body)
    return body[:start] + content + body[end:]


def apply_case_to_body(body: bytes, fuzz_case: FuzzCase) -> bytes:
    mutated = replace_filename(body, fuzz_case.filename)
    mutated = replace_part_content_type(mutated, fuzz_case)
    mutated = replace_file_content(mutated, fuzz_case.file_content)
    mutated = _insert_before_content_disposition(mutated, fuzz_case.prefix_content_disposition_lines)
    mutated = _insert_before_part_content_type(mutated, fuzz_case.prefix_content_type_lines)
    for old, new in fuzz_case.part_header_replacements:
        mutated = _replace_file_part_headers(mutated, _encode_header(old), _encode_header(new))
    if fuzz_case.filename_token is not None:
        mutated = replace_filename(mutated, fuzz_case.filename, fuzz_case.filename_token)
    return mutated


def _base_name(filename: str) -> str:
    clean = filename.replace("\x00", "")
    return clean.rsplit(".", 1)[0] if "." in clean else clean


def _case_id(category: str, detail: str, index: int) -> str:
    safe = detail.replace("\x00", "null")
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", safe).strip("_")[:56] or "case"
    digest = hashlib.md5(detail.encode("utf-8", errors="replace")).hexdigest()[:8]
    return f"{category}_{index:04d}_{safe}_{digest}"


def _long_filename(extension: str) -> str:
    suffix = "." + extension
    return "A" * (MAX_FILENAME_LENGTH - len(suffix)) + suffix


def _case_variations(extension: str) -> list[str]:
    if len(extension) > 5:
        return [extension.upper(), extension.lower(), extension.capitalize()]

    variations = {extension.upper(), extension.lower(), extension.capitalize()}
    if len(extension) >= 2:
        variations.add(extension[0].upper() + extension[1:].lower())
        variations.add(extension[0].lower() + extension[1:].upper())
        variations.add(extension[:-1].lower() + extension[-1].upper())
    if len(extension) >= 3:
        variations.add("".join(char.upper() if i % 2 == 0 else char.lower() for i, char in enumerate(extension)))
        variations.add("".join(char.lower() if i % 2 == 0 else char.upper() for i, char in enumerate(extension)))
    return list(variations)


def _safe_content_for_filename(filename: str) -> bytes:
    lowered = filename.lower()
    if lowered.endswith(".svg"):
        return SVG_BYTES
    if lowered in SAFE_CONFIG_CONTENTS:
        return SAFE_CONFIG_CONTENTS[lowered]
    return JPEG_BYTES


def generate_fuzz_cases(
    original_filename: str,
    original_content_type: str = "image/jpeg",
    target_languages: Iterable[str] = ("php", "asp", "aspx", "jsp"),
    max_payloads: int = MAX_PAYLOADS_DEFAULT,
) -> list[FuzzCase]:
    base = _base_name(original_filename) or "test"
    target_languages = [language for language in target_languages if language in BACKEND_LANGUAGES]
    cases: list[FuzzCase] = []
    seen_payload_keys: set[tuple] = set()

    def add(
        category: str,
        filename: str,
        content_type: str = "image/jpeg",
        file_content: bytes | None = None,
        reason: str = "",
        filename_token: str | None = None,
        remove_part_content_type: bool = False,
        content_type_line_template: str = "Content-Type: {content_type}",
        prefix_content_disposition_lines: tuple[str, ...] = (),
        prefix_content_type_lines: tuple[str, ...] = (),
        part_header_replacements: tuple[tuple[str, str], ...] = (),
    ) -> None:
        if len(filename) > MAX_FILENAME_LENGTH and not filename.startswith("A" * 50):
            return
        key = (
            category,
            filename,
            content_type,
            file_content or _safe_content_for_filename(filename),
            filename_token,
            remove_part_content_type,
            content_type_line_template,
            prefix_content_disposition_lines,
            prefix_content_type_lines,
            part_header_replacements,
        )
        if key in seen_payload_keys:
            return
        seen_payload_keys.add(key)
        cases.append(
            FuzzCase(
                case_id=_case_id(category, filename_token or filename or content_type, len(cases) + 1),
                category=category,
                filename=filename,
                content_type=content_type,
                file_content=file_content or _safe_content_for_filename(filename),
                reason=reason,
                filename_token=filename_token,
                remove_part_content_type=remove_part_content_type,
                content_type_line_template=content_type_line_template,
                prefix_content_disposition_lines=prefix_content_disposition_lines,
                prefix_content_type_lines=prefix_content_type_lines,
                part_header_replacements=part_header_replacements,
            )
        )

    add("control", f"{base}.jpg", original_content_type, JPEG_BYTES, "Allowed baseline with harmless JPEG marker content.")

    for language in target_languages:
        for pattern in SUFFIX_BYPASS_PATTERNS[language]:
            add("suffix", f"{base}.{pattern}", "image/jpeg", JPEG_BYTES, "Upload_Auto_Fuzz suffix bypass pattern with harmless content.")

    cd_variations = [
        ("Content-Disposition", "content-disposition"),
        ("Content-Disposition", "CONTENT-DISPOSITION"),
        ("Content-Disposition", "Content-disposition"),
        ("Content-Disposition", "ConTENT-DisPoSition"),
        ("Content-Disposition: ", "Content-Disposition:"),
        ("Content-Disposition: ", "Content-Disposition:  "),
        ("Content-Disposition: ", "Content-Disposition:\t"),
    ]
    fd_variations = [
        ("form-data", "Form-Data"),
        ("form-data", "FORM-DATA"),
        ("form-data", "form-Data"),
        ("form-data", "form-datA"),
        ("form-data; ", "form-data;"),
        ("form-data; ", "form-data;  "),
        ("form-data", "*"),
        ("form-data", "f+orm-data"),
        ("form-data", 'AAAA="BBBB"'),
        ("form-data; ", ""),
        ("form-data;", "form-data;;;;;;;;;;"),
        ("form-data;", "form-datA*;;;;;;;;;;"),
    ]
    for language in target_languages:
        ext = BACKEND_LANGUAGES[language][0]
        filename = f"{base}.{ext}"
        for old, new in cd_variations:
            add("content_disposition", filename, "image/jpeg", JPEG_BYTES, "Content-Disposition header-name/spacing mutation.", part_header_replacements=((old, new),))
        for old, new in fd_variations:
            add("content_disposition", filename, "image/jpeg", JPEG_BYTES, "form-data token mutation.", part_header_replacements=((old, new),))

        filename_variations = [
            f"filename={base}.{ext}",
            f"filename='{base}.{ext}'",
            f"filename=`{base}.{ext}`",
            f'filename="{base}.{ext}',
            f"filename='{base}.{ext}",
            f'filename="{base}.{ext}\'',
            f'filename=="{base}.{ext}"',
            f'filename==="{base}.{ext}"',
            f'filename===="{base}.{ext}"',
            "filename" + "=" * 50 + f'"{base}.{ext}"',
            f'filename="{base}.{ext}"\n',
            f'filename\n="{base}.{ext}"',
            f'filename=\n"{base}.{ext}"',
            f'filename="safe.jpg"; filename="{base}.{ext}"',
            f'filename="{base}.{ext}"; filename="safe.jpg"',
            f'filename="1.jpg";filename="{base}.{ext}"',
            f'filename= ;filename="{base}.{ext}"',
            f'filename="";filename="{base}.{ext}"',
            f'filename="{base}\\{ext}"',
            f'filename;;;;="{base}.{ext}"',
            f'filename;;;;;;;;;;;;;;="{base}.{ext}"',
            f'name="file";;;;;;;;;;;; filename="{base}.{ext}"',
        ]
        for token in filename_variations:
            add("content_disposition", filename, "image/jpeg", JPEG_BYTES, "filename parameter mutation.", filename_token=token)

    for language in target_languages:
        ext = BACKEND_LANGUAGES[language][0]
        executable_name = f"{base}.{ext}"
        for mime in CONTENT_TYPE_MIME_TYPES:
            add("content_type", executable_name, mime, JPEG_BYTES, "MIME type spoofing with harmless content.")
        for encoded_type in ["image%2Fgif", "image%2Fjpeg", "image%2Fphp", f"image%2F{ext}"]:
            add("content_type", executable_name, encoded_type, JPEG_BYTES, "URL-encoded Content-Type value.")
        add("content_type", executable_name, "", JPEG_BYTES, "Missing file-part Content-Type.", remove_part_content_type=True)
        for old, new in [
            ("Content-Type:", "content-type:"),
            ("Content-Type:", "CONTENT-TYPE:"),
            ("Content-Type: ", "Content-Type:"),
            ("Content-Type: ", "Content-Type:  "),
        ]:
            add("content_type", executable_name, "image/jpeg", JPEG_BYTES, "Content-Type header-name/spacing mutation.", part_header_replacements=((old, new),))
        add("content_type", executable_name, original_content_type, JPEG_BYTES, "Duplicate file-part Content-Type header.", prefix_content_type_lines=("Content-Type: image/gif",))

    for exec_type in ["application/x-httpd-php", "application/x-php", "text/x-php", "application/x-asp", "application/x-aspx"]:
        add("content_type", original_filename, exec_type, JPEG_BYTES, "Executable MIME value on original filename.")

    for language in target_languages:
        ext = BACKEND_LANGUAGES[language][0]
        for pattern in [f"{base}.{ext}::$DATA", f"{base}.{ext}::$DATA......", f"{base}:{ext}"]:
            add("windows_features", pattern, "image/jpeg", JPEG_BYTES, "NTFS alternate data stream filename pattern.")
        for pattern in [f"{base}.{ext};.jpg", f"{base}.{ext};.png", f"{base}.{ext};jpg"]:
            add("windows_features", pattern, "image/jpeg", JPEG_BYTES, "IIS semicolon filename pattern.")
        for device in WINDOWS_RESERVED_NAMES:
            add("windows_features", f"{device}.{ext}", "image/jpeg", JPEG_BYTES, "Windows reserved device filename.")
        for pattern in [f"{base}.{ext}.", f"{base}.{ext}..", f"{base}.{ext} ", f"{base}.{ext}. . ."]:
            add("windows_features", pattern, "image/jpeg", JPEG_BYTES, "Windows trailing dot/space normalization pattern.")

    for language in target_languages:
        ext = BACKEND_LANGUAGES[language][0]
        for pattern in [f"{base}.{ext}.jpg", f"{base}.{ext}.png", f"{base}.{ext}.gif", f"{base}.jpg.{ext}"]:
            add("linux_features", pattern, "image/jpeg", JPEG_BYTES, "Apache multi-extension filename pattern.")
        for pattern in [f"../{base}.{ext}", f"../../{base}.{ext}", f"../../../{base}.{ext}", f"..../{base}.{ext}", f"..\\{base}.{ext}"]:
            add("linux_features", pattern, "image/jpeg", JPEG_BYTES, "Path traversal filename pattern.")
        add("linux_features", f".{base}.{ext}", "image/jpeg", JPEG_BYTES, "Unix dotfile filename pattern.")
        add("linux_features", f"{base}.{ext}.", "image/jpeg", JPEG_BYTES, "Unix trailing-dot filename pattern.")

    for language in target_languages:
        ext = BACKEND_LANGUAGES[language][0]
        for magic_name, magic_bytes in MAGIC_BYTES.items():
            add("magic_bytes", f"{base}.{ext}", original_content_type, magic_bytes + MARKER, f"{magic_name} magic-byte prefix with harmless marker.")

    for language in target_languages:
        ext = BACKEND_LANGUAGES[language][0]
        for null in NULL_VARIANTS:
            for pattern in [f"{base}.{ext}{null}.jpg", f"{base}.{ext}{null}jpg", f"{base}{null}.{ext}"]:
                add("null_byte", pattern, "image/jpeg", JPEG_BYTES, "Null-byte representation in filename.")

    for language in target_languages:
        ext = BACKEND_LANGUAGES[language][0]
        full_name = f"{base}.{ext}"
        encoded_patterns = [
            f"{base}.%70%68%70" if ext == "php" else None,
            f"{base}.%61%73%70" if ext == "asp" else None,
            f"{base}.%6a%73%70" if ext == "jsp" else None,
            f"{base}.%2570%2568%2570" if ext == "php" else None,
            f"=?utf-8?B?{base64.b64encode(full_name.encode()).decode()}?=",
            f"=?utf-8?Q?{full_name.replace('.', '=2E')}?=",
            f"{base}.p\u0068p" if ext == "php" else None,
            f"{base}.ph\u0070" if ext == "php" else None,
        ]
        for pattern in encoded_patterns:
            if pattern:
                add("encoding", pattern, "image/jpeg", JPEG_BYTES, "Upload_Auto_Fuzz encoding-based filename pattern.")

    for language in target_languages:
        ext = BACKEND_LANGUAGES[language][0]
        add("waf_bypass", "A" * 200 + f".{ext}", "image/jpeg", JPEG_BYTES, "Oversized filename pattern.")
        add("waf_bypass", f"{base}.....{ext}", "image/jpeg", JPEG_BYTES, "Many-dot filename pattern.")
        add("waf_bypass", f"{base}.{ext}", "image/jpeg", JPEG_BYTES, "Large junk part header before Content-Disposition.", prefix_content_disposition_lines=("X-Junk: " + "A" * 500,))
        add("waf_bypass", f"{base}.{ext}", "image/jpeg", JPEG_BYTES, "Transfer-Encoding part-header mutation.", prefix_content_type_lines=("Transfer-Encoding: chunked",))
        add(
            "waf_bypass",
            f"{base}.{ext}",
            "image/jpeg",
            JPEG_BYTES,
            "Duplicate Content-Disposition part header.",
            prefix_content_disposition_lines=('Content-Disposition: form-data; name="decoy"; filename="safe.jpg"',),
        )

    for config_file in CONFIG_FILES:
        add("config_files", config_file, "text/plain", SAFE_CONFIG_CONTENTS.get(config_file, TEXT_BYTES), "Config filename probe with harmless marker content.")

    for language in target_languages:
        ext = BACKEND_LANGUAGES[language][0]
        for char in SPECIAL_CHARS:
            add("special_chars", f"{base}{char}.{ext}", "image/jpeg", JPEG_BYTES, "Special character before extension.")
            add("special_chars", f"{base}.{ext}{char}", "image/jpeg", JPEG_BYTES, "Special character after extension.")
            if len(ext) >= 2:
                mid = len(ext) // 2
                add("special_chars", f"{base}.{ext[:mid]}{char}{ext[mid:]}", "image/jpeg", JPEG_BYTES, "Special character inside extension.")
            add("special_chars", f"{base}{char}.{ext}", "image/jpeg", JPEG_BYTES, "Special character between basename and dot.")
        add("special_chars", f"{base}. {ext}", "image/jpeg", JPEG_BYTES, "Space after dot before extension.")
        add("special_chars", f"{base}...{ext}", "image/jpeg", JPEG_BYTES, "Multiple-dot filename pattern.")
        add("special_chars", f"{base}.....{ext}", "image/jpeg", JPEG_BYTES, "Many-dot filename pattern.")

    for language in target_languages:
        ext = BACKEND_LANGUAGES[language][0]
        for variation in _case_variations(ext):
            add("case_variation", f"{base}.{variation}", "image/jpeg", JPEG_BYTES, "Extension case variation.")

    for language in target_languages:
        ext = BACKEND_LANGUAGES[language][0]
        for allowed in DOUBLE_ALLOWED_EXTENSIONS:
            add("double_extension", f"{base}.{ext}.{allowed}", "image/jpeg", JPEG_BYTES, "Executable extension before allowed extension.")
            add("double_extension", f"{base}.{allowed}.{ext}", "image/jpeg", JPEG_BYTES, "Allowed extension before executable extension.")
            add("double_extension", f"{base}.{allowed}.{ext}.{allowed}", "image/jpeg", JPEG_BYTES, "Triple-extension filename pattern.")

    return cases[:max_payloads] if max_payloads > 0 else cases


def filter_cases(cases: Iterable[FuzzCase], categories: set[str] | None, limit: int) -> list[FuzzCase]:
    filtered = [case for case in cases if not categories or case.category in categories]
    return filtered[:limit] if limit > 0 else filtered


def _safe_path_name(case_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", case_id)


def _json_safe(value: str) -> str:
    return value.replace("\x00", "\\x00").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")


def request_target(request: RawRequest, base_url: str | None) -> tuple[str, str, int, str]:
    parsed_target = urlsplit(request.target)
    if parsed_target.scheme and parsed_target.netloc:
        scheme = parsed_target.scheme
        host = parsed_target.hostname or ""
        port = parsed_target.port or (443 if scheme == "https" else 80)
        path = parsed_target.path or "/"
        if parsed_target.query:
            path += "?" + parsed_target.query
        return scheme, host, port, path

    if base_url:
        parsed_base = urlsplit(base_url)
        if not parsed_base.scheme or not parsed_base.netloc:
            raise ValueError("--base-url must include scheme and host, e.g. https://target.example")
        scheme = parsed_base.scheme
        host = parsed_base.hostname or ""
        port = parsed_base.port or (443 if scheme == "https" else 80)
        return scheme, host, port, request.target

    host_header = get_header(request, "Host")
    if not host_header:
        raise ValueError("raw request has no absolute URL or Host header; provide --base-url")
    host, _, port_text = host_header.partition(":")
    port = int(port_text) if port_text else 80
    return "http", host, port, request.target


def send_request(request: RawRequest, body: bytes, base_url: str | None, timeout: float) -> dict:
    scheme, host, port, path = request_target(request, base_url)
    headers = {name: value for name, value in _headers_without_content_length(request.headers)}
    headers["Content-Length"] = str(len(body))

    if scheme == "https":
        context = ssl.create_default_context()
        connection: http.client.HTTPConnection = http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
    else:
        connection = http.client.HTTPConnection(host, port, timeout=timeout)

    started_at = time.time()
    try:
        connection.request(request.method, path, body=body, headers=headers)
        response = connection.getresponse()
        preview = response.read(4096)
        return {
            "status": response.status,
            "reason": response.reason,
            "duration_ms": int((time.time() - started_at) * 1000),
            "headers": dict(response.getheaders()),
            "body_preview": _decode_header(preview),
        }
    finally:
        connection.close()


def write_outputs(
    request: RawRequest,
    cases: Iterable[FuzzCase],
    output_dir: Path,
    send: bool,
    base_url: str | None,
    timeout: float,
    delay: float,
) -> list[dict]:
    output_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict] = []

    for fuzz_case in cases:
        body = apply_case_to_body(request.body, fuzz_case)
        raw_request = render_raw_request(request, body)
        raw_path = output_dir / f"{_safe_path_name(fuzz_case.case_id)}.raw.http"
        raw_path.write_bytes(raw_request)

        response = None
        if send:
            response = send_request(request, body, base_url, timeout)
            if delay > 0:
                time.sleep(delay)

        row = {
            "case_id": fuzz_case.case_id,
            "category": fuzz_case.category,
            "filename": _json_safe(fuzz_case.filename),
            "content_type": fuzz_case.content_type,
            "reason": fuzz_case.reason,
            "body_sha256": hashlib.sha256(fuzz_case.file_content).hexdigest(),
            "raw_request_path": str(raw_path),
            "sent": send,
            "response": response,
        }
        rows.append(row)

    cases_path = output_dir / "cases.jsonl"
    cases_path.write_text("\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n", encoding="utf-8")
    summary = {
        "case_count": len(rows),
        "output_dir": str(output_dir),
        "cases_path": str(cases_path),
        "sent": send,
        "categories": sorted({row["category"] for row in rows}),
    }
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    return rows


def load_raw_request(path_text: str | None) -> bytes:
    if not path_text:
        return SAMPLE_RAW_REQUEST
    if path_text == "-":
        return sys.stdin.buffer.read()
    return resolve_artifact_path(path_text).read_bytes()


def run_self_test(output_dir: Path, limit: int) -> dict:
    request = parse_raw_request(SAMPLE_RAW_REQUEST)
    original_filename = extract_original_filename(request.body)
    original_content_type = extract_part_content_type(request.body)
    cases = filter_cases(generate_fuzz_cases(original_filename, original_content_type, max_payloads=MAX_PAYLOADS_DEFAULT), None, limit)
    rows = write_outputs(request, cases, output_dir, send=False, base_url=None, timeout=5, delay=0)
    if not rows:
        raise AssertionError("self-test generated no cases")
    first_raw = Path(rows[0]["raw_request_path"]).read_bytes()
    if b"Content-Length:" not in first_raw or MARKER not in first_raw:
        raise AssertionError("self-test output is missing Content-Length or marker")
    forbidden_fragments = [b"<?php", b"<%", b"Runtime.getRuntime", b"SetHandler", b"auto_prepend_file", b"Process.Start"]
    for fuzz_case in cases:
        for fragment in forbidden_fragments:
            if fragment in fuzz_case.file_content:
                raise AssertionError(f"self-test generated unsafe content fragment: {fragment!r}")
    return {
        "status": "ok",
        "case_count": len(rows),
        "output_dir": str(output_dir),
        "categories": sorted({row["category"] for row in rows}),
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate safe full-strategy file-upload fuzz requests from a raw multipart upload packet.")
    parser.add_argument("--raw-request", help="Path to a captured raw multipart upload request. Use '-' for stdin. Defaults to a safe sample.")
    parser.add_argument("--output-dir", default="upload-fuzz-output", help="Directory for generated raw requests and JSONL metadata.")
    parser.add_argument("--limit", type=int, default=MAX_PAYLOADS_DEFAULT, help="Maximum cases to generate. Use 0 for all generated cases.")
    parser.add_argument("--categories", help="Comma-separated category filter, e.g. suffix,content_disposition,magic_bytes.")
    parser.add_argument("--target-languages", default="php,asp,aspx,jsp", help="Comma-separated backend language keys.")
    parser.add_argument("--send", action="store_true", help="Actually send generated requests in the isolated xSec environment; do not filter naturally discovered targets by initial scope.")
    parser.add_argument("--base-url", help="Scheme/host to use when the raw request target is relative, e.g. https://target.example.")
    parser.add_argument("--timeout", type=float, default=8.0, help="HTTP timeout in seconds.")
    parser.add_argument("--delay", type=float, default=0.2, help="Delay between sent requests.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable summary.")
    parser.add_argument("--self-test", action="store_true", help="Run against the built-in harmless multipart sample.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    output_dir = resolve_output_path(args.output_dir)

    if args.self_test:
        result = run_self_test(output_dir, args.limit)
        print(json.dumps(result, ensure_ascii=False) if args.json else f"self-test ok: {result['case_count']} cases -> {result['output_dir']}")
        return 0

    raw = load_raw_request(args.raw_request)
    request = parse_raw_request(raw)
    original_filename = extract_original_filename(request.body)
    original_content_type = extract_part_content_type(request.body)
    categories = {item.strip() for item in args.categories.split(",") if item.strip()} if args.categories else None
    target_languages = [item.strip() for item in args.target_languages.split(",") if item.strip()]
    cases = filter_cases(
        generate_fuzz_cases(
            original_filename=original_filename,
            original_content_type=original_content_type,
            target_languages=target_languages,
            max_payloads=MAX_PAYLOADS_DEFAULT,
        ),
        categories,
        args.limit,
    )

    if args.send and not args.raw_request:
        raise ValueError("--send requires --raw-request; do not send the built-in sample")

    rows = write_outputs(request, cases, output_dir, send=args.send, base_url=args.base_url, timeout=args.timeout, delay=args.delay)
    summary = {
        "case_count": len(rows),
        "output_dir": str(output_dir),
        "cases_path": str(output_dir / "cases.jsonl"),
        "sent": args.send,
        "categories": sorted({row["category"] for row in rows}),
    }
    if args.json:
        print(json.dumps(summary, ensure_ascii=False))
    else:
        print(f"generated {summary['case_count']} cases -> {summary['cases_path']}")
        if not args.send:
            print("dry-run only; add --send with --raw-request/--base-url to transmit")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)
