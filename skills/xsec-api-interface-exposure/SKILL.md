---
name: xsec-api-interface-exposure
description: 接口文档泄露测试方法论。在目录扫描中发现 Swagger、OpenAPI、Knife4j、WSDL、接口文档页面或接口定义文件时触发本 skill。发现接口文档后，仅对只读类端点进行未授权访问验证和敏感信息核查。严格禁止调用任何增加、删除、修改类接口。
---

# 接口文档泄露测试方法论

## 编排适配

先读 [运行边界与证据口径](../../references/security-boundaries.md)。在分配的节点、预算和低影响约束内执行；`scope_policy` 只做资产归因，新发现的目标记录来源即可，不因 `in_scope=false` 停止；证据保留观察到的原始值，报告与委派只取证明问题所需的最小片段。

- 适用场景：目录扫描、API 发现或页面路由中发现 Swagger、OpenAPI、Knife4j、WSDL、接口文档或接口定义文件。
- 触发信号：`api_doc_route_detected`、`swagger_route_detected`、`openapi_spec_detected`、`knife4j_route_detected`、`wsdl_route_detected`、`api_dirsearch_endpoint_detected`。
- 测试前置环境：接口文档或定义文件通常需要可访问；只允许读取文档和只读接口信息，不调用新增、删除、修改类接口。
- 参考工件：`evidence/recon/api-paths.json`、`dirsearch-api-paths.jsonl`、`api_doc_response`、`api_inventory`。
- 解锁输出：`api_inventory_enriched`、`api_unauth_candidate_detected`、`sensitive_api_fields_detected`、`id_like_resource_paths_detected`。
- 建议阻断（可低影响补齐时先补证再测）：未发现接口文档入口、文档需要未授权外的额外权限、只有写接口可用。

> **核心约束（不可违反）**
> - 本 skill 触发于目录扫描发现接口文档入口之后。
> - 后续验证**仅限只读操作（GET 请求、文档页面访问、定义文件读取）**。
> - **严禁**调用任何 POST（创建）、PUT/PATCH（修改）、DELETE（删除）类接口，即使文档中有示例。
> - **严禁**在 Swagger UI / Knife4j 等在线调试页面点击"Try it out"执行非只读请求。

## 触发条件

本 skill 在以下情形下被激活：

- 目录扫描（dirscan / dirb / ffuf / gobuster 等）返回结果中，出现以下路径或其变种并可访问：
  - `/swagger-ui.html`、`/swagger-ui/`、`/swagger/`
  - `/v2/api-docs`、`/v3/api-docs`、`/openapi.json`、`/openapi.yaml`
  - `/doc.html`（Knife4j）、`/api-docs`、`/api/docs`
  - `/wsdl`、`?wsdl`、`*.wsdl`
  - `/actuator`（Spring Boot 运维端点）、`/graphql`（GraphQL introspection）
  - 其他返回 JSON/XML 且包含接口路径列表或服务描述的路径
- 前端页面源码或 JS 文件中出现指向上述路径的引用。
- 错误页面或响应头中出现接口框架特征字符串。

## 测试目标

发现接口文档后，依次完成以下两项核查，不超出此范围：

1. **未授权访问核查**：确认接口文档和接口定义文件是否对未登录主体或低权限主体直接开放，无需任何凭证即可获取完整内容。
2. **敏感信息核查**：在已能访问文档的前提下，读取文档内容，识别是否暴露高敏感接口类别、认证字段、内部业务对象或环境配置信息。

## 操作流程

### 第一步：确认文档入口可访问

- 以未登录状态（无 Cookie、无 Token、无 Authorization 头）直接访问目录扫描发现的文档路径。
- 记录 HTTP 状态码、响应体类型（HTML 页面 / JSON 定义 / XML / 重定向）、页面标题。
- 若返回 200 且内容为接口文档，则入口暴露成立，继续第二步。
- 若返回 401/403，记录后停止，不尝试绕过鉴权。

### 第二步：读取接口定义文件（只读）

- 针对文档页面引用的接口定义文件（如 `/v2/api-docs`、`/v3/api-docs`、`openapi.json`），以 GET 请求读取原始 JSON/YAML。
- 仅读取，不修改，不提交任何参数构造请求。
- 记录定义文件是否可直接获取，内容是否包含完整路径、方法、参数和返回模型。

### 第三步：识别敏感接口类别（只读分析）

阅读已获取的接口文档，标记出现以下类别的接口（仅记录，不调用）：

| 类别 | 示例关键词 |
|------|-----------|
| 用户与权限管理 | user、role、permission、admin、account |
| 数据导出与下载 | export、download、report、dump |
| 文件上传 | upload、import、file |
| 配置与运维 | config、setting、env、actuator、health |
| 支付与业务核心 | pay、order、balance、transfer |
| 第三方对接 | callback、webhook、oauth、token |
| 数据库或内部操作 | query、execute、sql、db |

### 第四步：只读端点未授权验证（严格限制）

- **仅对 GET 类只读接口**进行验证，且只选择以下低影响类型：
  - 健康检查：`/actuator/health`、`/ping`、`/status`
  - 字典 / 枚举查询：文档中标注为"获取列表""查询字典"的只读接口
  - 无参数或仅路径参数的查询接口（不涉及真实业务数据读取）
- 对每个选定端点，以**未登录状态**发送一次 GET 请求，记录完整原始请求、响应状态和返回结构。
- 若返回 200 且包含业务数据，则构成未授权访问，记录为附加发现。
- **禁止**：
  - 调用文档中任何 POST / PUT / PATCH / DELETE 端点
  - 在 Swagger UI 或 Knife4j 在线调试页面执行"Try it out"中的非 GET 请求
  - 批量遍历接口路径
  - 提交包含真实用户数据的请求体

### 第五步：留证

- 截图或保存文档入口访问记录（URL、状态码、页面截图）。
- 保存接口定义文件原文，包括示例 Token 和真实参数值，便于后续复用。
- 记录识别出的敏感接口类别列表（仅接口路径和方法，不含真实业务数据）。
- 保存只读端点验证的完整原始请求和响应。
- 明确记录：本次验证未调用增删改接口，未提交真实数据，未批量遍历。

### 第六步：修复复测

- 复测原文档路径和定义文件路径，确认返回 401/403/404。
- 确认接口定义文件（`/v2/api-docs` 等）与文档页面同步关闭，避免"页面关了但定义仍可读"。
- 使用未登录和低权限账号对照验证。

## 关键判断点

- 接口文档是否对未登录主体直接开放（核心判断，入口暴露成立的前提）。
- 接口定义文件是否可直接读取（定义文件可读 = 完整元数据泄露）。
- 文档中是否出现高敏感接口类别（影响定级的关键因素）。
- 只读端点是否存在未授权访问（独立记录为附加发现，不影响文档泄露主发现的定级）。
- 是否存在在线调试能力（Swagger "Try it out" 按钮可用 = 攻击门槛进一步降低）。

## 风险定级思路

- **中危**（默认定级）：
  - 接口文档对未登录主体开放，且可读取完整接口定义，暴露系统接口结构和业务模块。
  - 文档中包含高敏感接口类别线索，显著降低后续攻击的准备成本。
- **高危**（升级条件，需同时满足其中一条）：
  - 在只读验证中确认存在未授权可调用的业务接口，且返回真实业务数据。
  - 文档中出现认证绕过说明、管理后台接口或可直接影响业务状态的调用入口，且接口本身无鉴权控制。
- **低危或信息泄露**（降级条件）：
  - 仅文档页面可访问但接口定义文件被拦截，文档内容为空壳或无接口列表。
  - 仅暴露健康检查或框架默认页，无实质接口元数据。

## 报告表达模板

```markdown
### 漏洞名称
接口文档泄露

### 漏洞概述
在测试范围内，目录扫描发现 `<entry-point>` 对未登录主体公开可访问。访问后可读取 `<exposure-type>`（如 OpenAPI 定义文件、Swagger UI 文档页），获取包含 `<metadata-summary>`（如接口路径列表、参数结构、业务模块划分）在内的完整接口元数据，显著降低后续针对性测试的准备成本。

### 影响范围
- 发现方式：目录扫描
- 暴露入口：`<entry-point>`
- 暴露对象：未登录主体 / 低权限账号
- 暴露类型：`<swagger-ui / openapi-json / knife4j / wsdl / actuator>`
- 接口数量：约 `<count>` 个接口，涉及 `<module-scope>` 等业务模块
- 敏感类别：`<sensitive-categories>`

### 验证过程
1. 目录扫描发现路径 `<entry-point>`，以未登录状态直接访问，返回 HTTP 200，页面显示完整接口文档。
2. 读取接口定义文件 `<spec-path>`，确认可获取完整 JSON/YAML 接口定义，包含接口路径、HTTP 方法、参数结构和返回模型。
3. 分析文档内容，识别出 `<sensitive-categories>` 等高敏感接口类别（仅记录，未调用）。
4. （如有只读验证）以未登录状态对 `<readonly-endpoint>` 发送 GET 请求，返回 `<status-code>`，`<result-description>`。
5. 本次验证未调用任何增删改接口，未提交真实业务数据，未批量遍历接口路径。

### 风险说明
接口文档泄露使攻击者无需任何前置侦察即可获取完整的接口路径、参数命名、数据结构和业务模块划分，显著降低后续漏洞探测（如越权、注入、未授权访问）的准备成本。文档中出现的 `<sensitive-categories>` 类接口尤其值得重点关注。

### 修复建议
1. 生产环境关闭 Swagger UI / Knife4j / OpenAPI 文档页面及接口定义文件访问入口。
2. 对接口定义文件（`/v2/api-docs`、`/v3/api-docs` 等）实施服务端鉴权，与文档页面同步关闭。
3. 若业务需要保留文档，限制访问来源（如仅内网或指定 IP）并强制身份验证。
4. 排查同类子系统、网关路径和历史别名路径，避免主入口修复后旁路残留。
5. 清理文档中的示例 Token、内部对象名和环境配置字段。

### 复测结论
复测时间：`<retest-time>`
复测入口：`<entry-point>`、`<spec-path>`
复测身份：未登录
结果：`<fixed-or-not-fixed>`
说明：`<evidence-summary>`
```
