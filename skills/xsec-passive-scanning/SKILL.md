---
name: xsec-passive-scanning
description: Web 安全测试中的被动扫描总入口与路由 Skill。用户需要复核 passive hook、mitmproxy、浏览器流量、DirSearch 代理流量或请求响应语料中自动落盘的敏感信息命中时应使用本 skill，尤其是需要按 target_skill/正则命中把秘钥泄露、SQL 报错、详细错误/路径泄露、内网地址泄露、指纹/API 文档、客户端暴露、对象存储桶 host、敏感字段、个人信息或 endpoint 线索分配给具体 Skill 生成报告时。该 skill 只做被动扫描结果去重、归类和子 Skill 路由，不替代具体漏洞判断。
---

# 被动扫描总入口

## 编排适配

- 适用场景：测试过程中 passive hook 已生成敏感信息、指纹、接口暴露或潜在漏洞线索命中，需要按 target_skill 去重、归类并派发专项复核。
- 触发信号：`passive_findings_available`、`passive_secret_match`、`passive_sql_error_match`、`passive_detailed_error_match`、`passive_path_leak_match`、`passive_internal_ip_match`、`passive_internal_hostname_match`、`passive_fingerprint_match`、`passive_api_doc_match`、`passive_client_exposure_match`、`passive_personal_info_match`、`passive_endpoint_match`、`passive_shiro_cookie_detected`、`passive_object_storage_bucket_detected`。
- 测试前置环境：必须已启用 browser traffic adapter 的 passive hook，并存在 `evidence/passive/*-passive-findings.jsonl`。
- 必需工件：`passive_findings`、`request_corpus`、`api_inventory`、`status_ledger`。
- 解锁输出：`cloud_secret_review_task`、`sql_error_review_task`、`error_path_review_task`、`internal_network_review_task`、`shiro_attack_detection_task`、`object_storage_bucket_review_task`。
- 阻断条件：没有 passive findings、命中无法归类或只有已确认的测试噪声。

本 Skill 是被动扫描能力域的总入口。它保留“被动扫描”这个概念，但不嵌套其他 Skill 目录；具体漏洞判断仍由平铺在 `skills/` 顶层的专项 Skill 执行。

## 适用场景

- 已有 `evidence/passive/*-passive-findings.jsonl`，需要在收尾前统一复核。
- passive hook 命中了秘钥、SQL 报错、详细错误、绝对路径、内网 IP/主机名、指纹、API 文档、source map、对象存储桶 host、敏感字段、个人信息或 endpoint。
- 主代理需要把被动扫描命中按 `target_skill` 分组，并分配给对应专项 Skill 生成发现/未发现报告。
- 需要避免把自动正则命中直接当成漏洞结论。

## 输入

优先读取这些紧凑 artifacts：

- `evidence/passive/*-passive-findings.jsonl`
- `evidence/orchestrator/status.json`
- 相关 `evidence/corpus/request-corpus.jsonl`
- 相关 `evidence/corpus/api-inventory.json`

不要整读完整 flows、HAR、HTML、截图或大响应体。需要证明时，通过 `request_id`、`path`、`pattern_id`、`match_hash` 定位最小请求/响应片段。

## 路由规则

按 passive finding 中的 `target_skill` 优先路由：

| 命中类别 | 信号 | 具体 Skill |
| --- | --- | --- |
| 云密钥、私钥、Token、AK/SK | `passive_secret_match`、`passive_private_key_match` | `../xsec-cloud-secret-leakage` |
| SQL/ORM/数据库错误 | `passive_sql_error_match` | `../xsec-sql-error-info-leak` |
| 详细错误、堆栈、绝对路径 | `passive_detailed_error_match`、`passive_path_leak_match` | `../xsec-error-path-leakage` |
| 内网 IP、内部主机名、内部端口线索 | `passive_internal_ip_match`、`passive_internal_hostname_match` | `../xsec-internal-network-leakage` |
| API 文档、接口路径、URL 线索 | `passive_api_doc_match`、`passive_endpoint_match`、`passive_url_match` | `../xsec-api-interface-exposure` |
| 前端 HTML/JS 中提取到的疑似后端 path | `frontend_endpoint_path_candidate_detected` | `../xsec-unauth-access` |
| 客户端源码、source map、前端路由 | `passive_client_exposure_match`、`source_map_detected`、`frontend_route_inventory_detected` | `../xsec-client-hardcoded-secret` |
| Shiro Cookie 指纹 | `passive_shiro_cookie_detected` | `../xsec-shiro-attack-detection` |
| 对象存储桶 host、OSS/COS/OBS/S3 直链 | `passive_object_storage_bucket_detected` | `../xsec-object-storage-bucket` |
| 上传、SSRF、文件读取、浏览器存储线索 | `passive_upload_form_match`、`passive_url_value_match`、`passive_file_read_match`、`passive_browser_storage_match` | finding 中的 `target_skill` |
| 个人信息、账号字段、手机号字段 | `passive_personal_info_match`、`passive_username_field_match`、`passive_basic_info_match` | finding 中的 `target_skill`；缺失时仅记录 observation |

如果 `target_skill` 缺失，则按 `signal` 和 `category` fallback 到上表。无法归类的命中只记录为 observation，不生成漏洞结论。

## 执行流程

1. 汇总所有 `passive-findings.jsonl`。
2. 按 `target_skill + pattern_id + match_hash + host + path + location` 去重。
3. 把每组命中整理为 compact evidence set：命中数量、首末时间、host/path、status、location、pattern_id、signal、脱敏 preview、request_id 列表。
4. 对每组 evidence set 启动对应专项 Skill 子代理。
5. 专项 Skill 必须做最小化判断：确认是有效泄露、低价值信息、误报、已脱敏占位、测试数据，还是证据不足。
6. 发现问题时生成 `reports/<系统名称>/<漏洞名称>.md`；未发现或误报时生成 `reports/<系统名称>/not-found/<漏洞名称>.md`。
7. 返回给主代理的 JSON 中必须包含分组结果、被调用专项 Skill、report paths、not_found paths 和未覆盖限制。

## 判断边界

- passive hook 命中只是候选，不是最终漏洞。
- 报告中不得写入完整秘钥、完整 token、完整 Cookie、完整个人信息或大段响应体。
- 对秘钥类命中，只验证来源、可获取性、类型、有效性边界和最小权限，不接管真实资源。
- 对内网地址类命中，不主动扫描内网，只判断泄露线索是否对外可见、是否稳定、是否具有环境认知价值。
- 对对象存储桶命中，先按 host 去重；默认只做匿名只读检查，未明确时不做 canary 上传，也不写 ACL/Policy。
- 对错误信息类命中，优先证明服务端把诊断信息返回给了前端，而不是扩展成破坏性测试。

## 输出契约

返回 compact JSON：

```json
{
  "ok": true,
  "agent": "passive-sensitive-review",
  "skill_id": "xsec-passive-scanning",
  "groups": [
    {
      "target_skill": "../xsec-sql-error-info-leak",
      "signals": ["passive_sql_error_match"],
      "count": 3,
      "evidence": ["evidence/passive/scout-passive-findings.jsonl"],
      "status": "dispatched"
    }
  ],
  "issues": [],
  "not_found": [],
  "outputs": {
    "summary": "evidence/agents/passive-sensitive-review/summary.json"
  }
}
```
