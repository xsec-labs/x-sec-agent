---
name: xsec-object-storage-bucket
description: 针对主流云对象存储桶（阿里云 OSS、腾讯云 COS、华为云 OBS、AWS S3）的授权被动发现与低影响安全检测方法论。用户需要根据 passive hook、浏览器流量、对象存储直链、OSS/COS/OBS/S3 域名、NoSuchBucket、ListBucketResult、ACL/Policy 暴露、匿名上传、桶接管候选或 BucketTool 风格检测结果来验证存储桶安全问题时，应使用本 skill。尤其适用于被动扫描发现 bucket host 后，按 host 去重并检查桶遍历、未授权上传、ACL/Policy 配置暴露、桶接管候选和对象存储访问控制边界。
---

# 对象存储桶安全检测方法论

## 编排适配

- 适用场景：passive hook、浏览器流量、上传/下载/预览链路或前端资源中出现 OSS/COS/OBS/S3 bucket host，需要对对象存储桶做专项复核。
- 触发信号：`passive_object_storage_bucket_detected`、`object_storage_bucket_detected`、`object_storage_listing_detected`、`object_storage_upload_allowed`、`object_storage_acl_policy_exposed`、`bucket_takeover_candidate`。
- 测试前置环境：必须有 bucket host 或对象存储自定义域名；
- 必需工件：`passive_findings`、`bucket_host`、`bucket_provider`、`request_corpus`、`flow`、`allowed_bucket_verification_scope`。
- 解锁输出：`object_storage_listing_detected`、`object_storage_upload_allowed`、`object_storage_acl_policy_exposed`、`bucket_takeover_candidate`、`cloud_storage_issue_validated`、`vulnerability_chain_input`。
- 阻断条件：只能证明普通 CDN/静态资源访问、写入探测未授权、检测会访问真实敏感对象或需要修改 ACL/Policy 配置。

本 skill 借鉴 BucketTool 的检测思路：先识别云厂商和 bucket，再检查匿名列表、匿名上传、ACL/Policy 暴露和 NoSuchBucket 接管候选。项目内实现使用 `scripts/bucket_check.py`，默认只做匿名只读检查；`--allow-write-probes` 才会创建一个小型 canary 文件并尝试清理。

## 输入处理

优先从 passive findings 读取候选：

```bash
python3 skills/xsec-object-storage-bucket/scripts/bucket_check.py \
  --input-jsonl evidence/passive/scout-passive-findings.jsonl \
  --out evidence/agents/object-storage-bucket/bucket-check-results.json
```

也可以直接指定 bucket URL 或 host：

```bash
python3 skills/xsec-object-storage-bucket/scripts/bucket_check.py \
  https://example-bucket.oss-cn-beijing.aliyuncs.com/ \
  https://example-1250000000.cos.ap-shanghai.myqcloud.com/ \
  https://example-bucket.obs.cn-north-4.myhuaweicloud.com/ \
  https://example-bucket.s3.us-east-1.amazonaws.com/
```

如果允许匿名上传验证，才加入写入探测：

```bash
python3 skills/xsec-object-storage-bucket/scripts/bucket_check.py \
  --input-jsonl evidence/passive/scout-passive-findings.jsonl \
  --allow-write-probes \
  --out evidence/agents/object-storage-bucket/bucket-check-results.json
```

## 检测流程

1. 按 `bucket_provider + host + bucket_name` 去重，只对每个 host 测一次。
2. 识别 provider：
   - 阿里云 OSS：`*.oss-*.aliyuncs.com`
   - 腾讯云 COS：`*.cos.*.myqcloud.com`
   - 华为云 OBS：`*.obs.*.myhuaweicloud.com`
   - AWS S3：`*.s3.*.amazonaws.com`、`*.s3.amazonaws.com`、`*.s3-website.*.amazonaws.com`
3. 执行匿名只读检查：
   - `GET <bucket-root>` 或 AWS `GET <bucket-root>?list-type=2`，判断是否返回 `ListBucketResult`。
   - `GET <bucket-root>?acl`，判断 ACL 是否匿名可读。
   - `GET <bucket-root>?policy`，判断 Policy 是否匿名可读。
   - `GET <bucket-root>`，判断是否返回 `NoSuchBucket`，作为桶接管候选。
4. 明确允许时，执行匿名 PUT canary：
   - 上传 `xsec-passive-bucket-check/<random>.txt`。
   - 2xx 视为匿名上传候选。
   - 上传成功后尝试 DELETE 清理；如果清理失败，在报告中说明残留路径并交给授权方清理。
5. 不执行 ACL/Policy 写入探测，除非明确允许并另行指定专门测试窗口。写 ACL/Policy 会修改云资源配置，不能作为默认被动扫描动作。

## 判断边界

- `passive_object_storage_bucket_detected` 只是候选，不能直接写成漏洞。
- 公开静态资源桶不一定有漏洞；只有未授权列举、未授权上传、ACL/Policy 暴露、NoSuchBucket 接管候选或访问控制越界才进入 finding。
- 匿名上传成功但无法访问对象，仍说明写入边界有问题；风险等级要结合对象是否可读、是否可覆盖、是否会产生费用或内容污染。
- `NoSuchBucket` 在云厂商标准 endpoint 上只是接管候选；若是业务自定义域名 CNAME 到不存在 bucket，风险更高，需要保留 DNS/CNAME 与响应证据。
- 不下载真实业务对象，不全量翻页遍历，不递归枚举前缀，不删除或修改已有对象，不写 ACL/Policy。

## 证据要求

- 被动发现证据：`passive-findings.jsonl` 中的 host、provider、request_id、status、path。
- 验证证据：`bucket-check-results.json` 中每个 check 的 Burp Raw 风格请求/响应、状态码、短响应 preview。
- 截图证据：优先截图对象存储 XML/错误页面或报告中的响应展示面；纯 API 证据无法截图时说明原因。
- 写入证据：只展示 canary 对象路径、PUT 状态码和清理状态，不保留敏感对象内容。
- 报告中所有 bucket 名、对象 key、域名可按客户要求输出，但要保留 provider、风险类型和证据链。

## 输出契约

返回 compact JSON，并生成 found/not-found Markdown：

```json
{
  "ok": true,
  "skill_id": "xsec-object-storage-bucket",
  "checked_hosts": ["example-bucket.oss-cn-beijing.aliyuncs.com"],
  "issues": [
    {
      "type": "object_storage_listing_detected",
      "host": "example-bucket.oss-cn-beijing.aliyuncs.com",
      "provider": "aliyun_oss",
      "report": "reports/<系统名称>/对象存储桶遍历.md",
      "evidence": "evidence/agents/object-storage-bucket/bucket-check-results.json"
    }
  ],
  "not_found": [],
  "unlocked_signals": ["cloud_storage_issue_validated", "vulnerability_chain_input"]
}
```

## 报告表达模板

```markdown
### 漏洞名称
对象存储桶安全配置缺陷

### 漏洞概述
在测试范围内，测试人员通过被动流量发现 `<bucket-host>`，并对该对象存储桶执行低影响验证。结果显示 `<issue-type>`，可能导致 `<impact-summary>`。

### 验证过程
1. passive hook 在 `<request-id>` 对应流量中发现 `<provider>` bucket host：`<bucket-host>`。
2. 使用匿名请求访问 `<sanitized-check-url>`，响应状态为 `<status>`，响应片段包含 `<evidence-marker>`。
3. 测试未下载真实业务对象，未递归遍历前缀，未修改 ACL/Policy。若执行了 canary PUT，已记录清理状态：`<cleanup-status>`。

### 风险说明
该问题可能造成对象清单泄露、未授权写入、对象污染、费用损失、配置策略暴露或桶接管风险。实际影响取决于桶用途、对象敏感度、写入后可访问性和自定义域名绑定关系。

### 修复建议
1. 禁止匿名 ListBucket、PutObject、GetBucketAcl、GetBucketPolicy 等非必要权限。
2. 使用最小权限 bucket policy，按业务身份、对象前缀、动作和来源条件收敛访问。
3. 前端直传只使用短期受限凭据，绑定用户、业务对象、前缀、文件大小和过期时间。
4. 检查自定义域名 CNAME，删除指向不存在 bucket 的绑定，避免接管。
5. 开启对象存储访问日志和异常告警，排查历史匿名访问与写入。
```
