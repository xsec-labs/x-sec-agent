#!/usr/bin/env python3
"""Low-impact object storage bucket checks for testing."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
import uuid
from dataclasses import dataclass, asdict
from pathlib import Path
from urllib import error, request
from urllib.parse import quote, urlparse, urlunparse

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts"))
from xsec_paths import resolve_artifact_path, resolve_output_path


USER_AGENT = "xSecAgent-bucket-check/1.0"
MAX_PREVIEW_CHARS = 2000


@dataclass(frozen=True)
class BucketTarget:
    original: str
    base_url: str
    host: str
    bucket_provider: str
    vendor: str
    bucket_name: str
    region: str
    endpoint_style: str


def compact(obj: dict) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def normalize_host(host: str) -> str:
    normalized = (host or "").strip().lower().rstrip(".")
    if normalized.count(":") == 1:
        normalized = normalized.split(":", 1)[0]
    return normalized


def first_path_segment(path: str) -> str:
    path = (path or "").split("?", 1)[0].split("#", 1)[0].lstrip("/")
    return path.split("/", 1)[0] if path else ""


def is_plausible_bucket_name(value: str) -> bool:
    return bool(value and len(value) <= 128 and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{1,126}[A-Za-z0-9]", value))


def provider_info(provider: str, vendor: str, bucket: str, region: str, endpoint_style: str) -> dict | None:
    if not is_plausible_bucket_name(bucket):
        return None
    return {
        "bucket_provider": provider,
        "vendor": vendor,
        "bucket_name": bucket,
        "region": region,
        "endpoint_style": endpoint_style,
    }


def detect_provider(host: str, path: str = "") -> dict | None:
    host = normalize_host(host)
    path_bucket = first_path_segment(path)
    virtual_hosted = [
        (r"^(?P<bucket>.+)\.(?P<region>oss-[a-z0-9-]+(?:-internal)?|oss-accelerate(?:-overseas)?)\.aliyuncs\.com$", "aliyun_oss", "阿里云 OSS"),
        (r"^(?P<bucket>.+)\.cos\.(?P<region>[a-z0-9-]+)\.myqcloud\.com$", "tencent_cos", "腾讯云 COS"),
        (r"^(?P<bucket>.+)\.obs\.(?P<region>[a-z0-9-]+)\.myhuaweicloud\.(?:com|cn)$", "huawei_obs", "华为云 OBS"),
        (r"^(?P<bucket>.+)\.s3[.-](?P<region>[a-z0-9-]+)\.amazonaws\.com(?:\.cn)?$", "aws_s3", "AWS S3"),
        (r"^(?P<bucket>.+)\.s3\.amazonaws\.com(?:\.cn)?$", "aws_s3", "AWS S3"),
        (r"^(?P<bucket>.+)\.s3-website[.-](?P<region>[a-z0-9-]+)\.amazonaws\.com(?:\.cn)?$", "aws_s3", "AWS S3"),
    ]
    for regex, provider, vendor in virtual_hosted:
        match = re.match(regex, host)
        if match:
            return provider_info(provider, vendor, match.group("bucket"), match.groupdict().get("region", ""), "virtual_hosted")

    path_style = [
        (r"^oss-[a-z0-9-]+(?:-internal)?\.aliyuncs\.com$", "aliyun_oss", "阿里云 OSS"),
        (r"^cos\.(?P<region>[a-z0-9-]+)\.myqcloud\.com$", "tencent_cos", "腾讯云 COS"),
        (r"^obs\.(?P<region>[a-z0-9-]+)\.myhuaweicloud\.(?:com|cn)$", "huawei_obs", "华为云 OBS"),
        (r"^s3(?:[.-](?P<region>[a-z0-9-]+))?\.amazonaws\.com(?:\.cn)?$", "aws_s3", "AWS S3"),
    ]
    for regex, provider, vendor in path_style:
        match = re.match(regex, host)
        if match and path_bucket:
            return provider_info(provider, vendor, path_bucket, match.groupdict().get("region", ""), "path_style")
    return None


def target_from_url(raw: str) -> BucketTarget | None:
    candidate = raw.strip()
    if not candidate:
        return None
    if "://" not in candidate:
        candidate = "https://" + candidate
    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    info = detect_provider(parsed.hostname or "", parsed.path)
    if not info:
        info = provider_info("unknown_object_storage", "未知对象存储", parsed.hostname or parsed.netloc, "", "custom_or_unknown")
    if not info:
        return None
    base_path = ""
    if info["endpoint_style"] == "path_style":
        base_path = "/" + quote(info["bucket_name"])
    base_url = urlunparse((parsed.scheme, parsed.netloc, base_path or "/", "", "", ""))
    return BucketTarget(
        original=raw,
        base_url=base_url,
        host=normalize_host(parsed.hostname or parsed.netloc),
        bucket_provider=info["bucket_provider"],
        vendor=info["vendor"],
        bucket_name=info["bucket_name"],
        region=info["region"],
        endpoint_style=info["endpoint_style"],
    )


def with_query(base_url: str, query: str) -> str:
    parsed = urlparse(base_url)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", query, ""))


def object_url(base_url: str, key: str) -> str:
    parsed = urlparse(base_url)
    base_path = (parsed.path or "/").rstrip("/")
    path = f"{base_path}/{quote(key)}"
    return urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))


def raw_request(method: str, url: str, headers: dict[str, str], body: bytes | None) -> str:
    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    lines = [f"{method} {path} HTTP/1.1", f"Host: {parsed.netloc}"]
    for key, value in headers.items():
        if key.lower() != "host":
            lines.append(f"{key}: {value}")
    lines.append("")
    text = "\r\n".join(lines) + "\r\n"
    if body:
        text += body.decode("utf-8", errors="replace")
    return text


def raw_response(status: int, headers: dict[str, str], body: str) -> str:
    lines = [f"HTTP/1.1 {status}"]
    for key, value in headers.items():
        lines.append(f"{key}: {value}")
    lines.append("")
    return "\r\n".join(lines) + "\r\n" + body[:MAX_PREVIEW_CHARS]


def http_request(method: str, url: str, timeout: float, max_bytes: int, body: bytes | None = None, extra_headers: dict[str, str] | None = None) -> dict:
    headers = {"User-Agent": USER_AGENT}
    if extra_headers:
        headers.update(extra_headers)
    req = request.Request(url, data=body, headers=headers, method=method)
    started = time.time()
    try:
        with request.urlopen(req, timeout=timeout) as resp:
            data = resp.read(max_bytes + 1)
            status = resp.status
            response_headers = dict(resp.headers.items())
    except error.HTTPError as exc:
        data = exc.read(max_bytes + 1)
        status = exc.code
        response_headers = dict(exc.headers.items())
    except Exception as exc:
        return {
            "ok": False,
            "error": type(exc).__name__,
            "error_detail": str(exc)[:300],
            "status": 0,
            "url": url,
            "duration_ms": int((time.time() - started) * 1000),
            "request": raw_request(method, url, headers, body),
            "response": "",
        }
    text = data[:max_bytes].decode("utf-8", errors="replace")
    return {
        "ok": True,
        "status": status,
        "headers": response_headers,
        "body_preview": text[:MAX_PREVIEW_CHARS],
        "truncated": len(data) > max_bytes,
        "url": url,
        "duration_ms": int((time.time() - started) * 1000),
        "request": raw_request(method, url, headers, body),
        "response": raw_response(status, response_headers, text),
    }


def finding_check(check_id: str, title: str, method: str, url: str, severity: str, found: bool, result: dict, evidence: str = "", cleanup: dict | None = None) -> dict:
    item = {
        "id": check_id,
        "title": title,
        "method": method,
        "url": url,
        "status": result.get("status", 0),
        "found": found,
        "severity_hint": severity,
        "evidence": evidence,
        "duration_ms": result.get("duration_ms", 0),
        "request": result.get("request", ""),
        "response": result.get("response", ""),
    }
    if result.get("error"):
        item["error"] = result["error"]
        item["error_detail"] = result.get("error_detail", "")
    if cleanup is not None:
        item["cleanup"] = cleanup
    return item


def looks_like_listing(body: str) -> bool:
    lowered = body.lower()
    return "<listbucketresult" in lowered and ("<name>" in lowered or "<contents>" in lowered or "<key>" in lowered)


def looks_like_acl(body: str) -> bool:
    lowered = body.lower()
    return any(marker in lowered for marker in ("<accesscontrolpolicy", "<accesscontrollist", "<permission>", "<grant>", "<owner>"))


def looks_like_policy(body: str) -> bool:
    lowered = body.lower()
    return '"statement"' in lowered or '"version"' in lowered or "accessdenied" not in lowered and "policy" in lowered


def looks_like_no_such_bucket(body: str) -> bool:
    lowered = body.lower()
    return "nosuchbucket" in lowered or "<code>no such bucket</code>" in lowered


def planned_checks(target: BucketTarget, allow_write: bool) -> list[dict]:
    listing_url = with_query(target.base_url, "list-type=2") if target.bucket_provider == "aws_s3" else target.base_url
    checks = [
        {"id": "bucket_listing", "method": "GET", "url": listing_url},
        {"id": "acl_read", "method": "GET", "url": with_query(target.base_url, "acl")},
        {"id": "policy_read", "method": "GET", "url": with_query(target.base_url, "policy")},
        {"id": "bucket_takeover_candidate", "method": "GET", "url": target.base_url},
    ]
    if allow_write:
        checks.append({"id": "anonymous_upload", "method": "PUT", "url": object_url(target.base_url, "xsec-passive-bucket-check/<canary>.txt")})
    return checks


def scan_target(target: BucketTarget, timeout: float, max_bytes: int, allow_write: bool, cleanup_upload: bool, dry_run: bool) -> dict:
    result = {
        "target": asdict(target),
        "target_hash": hashlib.sha256(f"{target.bucket_provider}:{target.host}".encode()).hexdigest()[:24],
        "checks": [],
        "findings": [],
        "planned_checks": planned_checks(target, allow_write),
    }
    if dry_run:
        return result

    listing_url = with_query(target.base_url, "list-type=2") if target.bucket_provider == "aws_s3" else target.base_url
    listing = http_request("GET", listing_url, timeout, max_bytes)
    listing_found = listing.get("ok") and 200 <= int(listing.get("status", 0)) < 300 and looks_like_listing(listing.get("body_preview", ""))
    result["checks"].append(finding_check("bucket_listing", "匿名桶遍历/列举", "GET", listing_url, "high", bool(listing_found), listing, "response contains ListBucketResult"))

    acl_url = with_query(target.base_url, "acl")
    acl = http_request("GET", acl_url, timeout, max_bytes)
    acl_found = acl.get("ok") and 200 <= int(acl.get("status", 0)) < 300 and looks_like_acl(acl.get("body_preview", ""))
    result["checks"].append(finding_check("acl_read", "ACL 匿名可读", "GET", acl_url, "medium", bool(acl_found), acl, "response contains ACL markers"))

    policy_url = with_query(target.base_url, "policy")
    policy = http_request("GET", policy_url, timeout, max_bytes)
    policy_found = policy.get("ok") and 200 <= int(policy.get("status", 0)) < 300 and looks_like_policy(policy.get("body_preview", ""))
    result["checks"].append(finding_check("policy_read", "Policy 匿名可读", "GET", policy_url, "medium", bool(policy_found), policy, "response contains policy markers"))

    takeover = http_request("GET", target.base_url, timeout, max_bytes)
    takeover_found = takeover.get("ok") and int(takeover.get("status", 0)) in {404, 409} and looks_like_no_such_bucket(takeover.get("body_preview", ""))
    result["checks"].append(finding_check("bucket_takeover_candidate", "桶接管候选", "GET", target.base_url, "high", bool(takeover_found), takeover, "response contains NoSuchBucket"))

    if allow_write:
        key = f"xsec-passive-bucket-check/{int(time.time())}-{uuid.uuid4().hex}.txt"
        upload_url = object_url(target.base_url, key)
        body = b"xsec bucket canary\n"
        upload = http_request("PUT", upload_url, timeout, max_bytes, body=body, extra_headers={"Content-Type": "text/plain"})
        upload_found = upload.get("ok") and 200 <= int(upload.get("status", 0)) < 300
        cleanup = None
        if upload_found and cleanup_upload:
            cleanup_result = http_request("DELETE", upload_url, timeout, max_bytes)
            cleanup = {"attempted": True, "status": cleanup_result.get("status", 0), "ok": cleanup_result.get("ok", False)}
        result["checks"].append(finding_check("anonymous_upload", "匿名 PUT 上传", "PUT", upload_url, "high", bool(upload_found), upload, "PUT canary returned 2xx", cleanup))

    result["findings"] = [item for item in result["checks"] if item.get("found")]
    return result


def load_targets(args: argparse.Namespace) -> list[str]:
    targets: list[str] = list(args.targets or [])
    if args.targets_file:
        targets.extend(line.strip() for line in resolve_artifact_path(args.targets_file).read_text(encoding="utf-8").splitlines() if line.strip())
    if args.input_jsonl:
        for line in resolve_artifact_path(args.input_jsonl).read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if item.get("signal") != "passive_object_storage_bucket_detected" and item.get("category") != "object_storage_bucket":
                continue
            host = item.get("bucket_host") or item.get("host")
            if host:
                targets.append("https://" + str(host).strip())
    deduped = []
    seen = set()
    for raw in targets:
        target = target_from_url(raw)
        if not target:
            continue
        key = f"{target.bucket_provider}:{target.host}:{target.bucket_name}"
        if key in seen:
            continue
        seen.add(key)
        deduped.append(raw)
    return deduped


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check public object storage bucket exposure with low-impact probes.")
    parser.add_argument("targets", nargs="*", help="Bucket URL or host. Hosts without scheme default to https.")
    parser.add_argument("--input-jsonl", help="Passive findings JSONL containing passive_object_storage_bucket_detected entries.")
    parser.add_argument("--targets-file", help="Plain text file of bucket URLs/hosts.")
    parser.add_argument("--out", help="Write JSON results to this path.")
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--max-response-bytes", type=int, default=65536)
    parser.add_argument("--allow-write-probes", action="store_true", help="Enable explicit canary PUT checks in the isolated xSec environment; discovered bucket hosts are not filtered by initial scope.")
    parser.add_argument("--no-cleanup-upload", action="store_true", help="Do not attempt DELETE cleanup after a successful canary upload.")
    parser.add_argument("--dry-run", action="store_true", help="Only parse targets and show planned checks.")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    raw_targets = load_targets(args)
    targets = [target for raw in raw_targets if (target := target_from_url(raw))]
    results = [
        scan_target(
            target,
            timeout=args.timeout,
            max_bytes=args.max_response_bytes,
            allow_write=args.allow_write_probes,
            cleanup_upload=not args.no_cleanup_upload,
            dry_run=args.dry_run,
        )
        for target in targets
    ]
    findings_count = sum(len(item.get("findings", [])) for item in results)
    output = {
        "ok": True,
        "generated_at": time.time(),
        "target_count": len(targets),
        "summary": {
            "findings_count": findings_count,
            "write_probes_enabled": bool(args.allow_write_probes),
            "dry_run": bool(args.dry_run),
        },
        "results": results,
    }
    if args.out:
        out_path = resolve_output_path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    print(compact(output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
