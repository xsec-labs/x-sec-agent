# 主代理编排指南

主代理负责测试流程，而不是具体漏洞测试细节。主代理根据观察信号按需触发漏洞 Skill，分配子代理，并维护实时进度、问题清单和战果列表。

## 何时读取

当你是主代理，或用户要求编排 Web 安全测试流程时，读取本文件。不要读取 `references/vulnerability-subagent.md`，除非你需要核对将要发给子代理的 payload 字段。

## 主代理职责

- 确认目标、账号和速率限制。
- 读取 `config/vulnerability-skills.yaml`。
- 读取 `scenario_playbooks`、`orchestration_model`、`autonomy`、`vulnerability_skills` 和 `post_processors`；把 playbook 当作常见场景提示，把每个 Skill 的 `activation` 当作注册派发条件。
- 选择 browser traffic adapter，默认是 `web-pentest-browser-flow`。
- 在测试初期创建并行侦查子代理，至少覆盖站点性质判断、API 路径发现、登录入口归集和必要的 DirSearch。
- 确保浏览器、DirSearch、弱口令和漏洞验证流量都经过 browser traffic adapter 启动的 mitm proxy 与 passive hook。
- 为每个 mitm proxy 手动分配 `20000-60999` 区间内的高位随机端口，并在 payload、`--port` 和 `--proxy` 中保持一致。端口占用或启动失败时，Agent 手动换另一个高位随机端口；不要使用 `8081/8082/8083` 这类固定低位顺序端口，也不要依赖默认端口。
- 做基线 scout，生成 forms、actions、routes、API inventory、request corpus、frontend asset inventory、匿名响应样本和 passive findings。
- 根据 observations 和 activation 条件触发漏洞 Skill。
- 触发前同时检查 `activation.requires_environment`、`activation.requires_artifacts`、全局阻断信号；环境不存在时只记录 `blocked` 或 `waiting_for_artifact`，不启动子代理。
- 对注册表没有覆盖但证据合理的新线索，写入 `hypothesis_queue`；允许做一次低影响确认或补充侦查，确认后转成 observation、next_action 或新增 Skill 建议。
- 为每个已触发漏洞 Skill 分配 system_name、子代理、proxy、flow、browser state、evidence 目录、证据级别和报告交付门禁。
- 持续更新 `evidence/orchestrator/status.json`。
- 如果用户提供了测试账号密码，优先直接登录并保存 browser state，再进入登录后测试分配；不要把“弱口令测试”作为获得登录态的必要前置。
- 汇总子代理返回的 observations、finding candidates、validated issues、not_found、wins、evidence paths、annotated screenshot paths 和 Markdown report paths。
- 把子代理返回的 `unlocks_on_success` 对应信号写入 observations/wins，然后重新计算队列；前一个节点的战果只解锁后续节点，不等于后续节点已经确认存在漏洞。
- 结束前安排 passive findings 复核子代理；如果发现敏感信息命中，按对应 passive Skill 生成发现或未发现报告。
- 结束前尝试调用 `xsec-vulnerability-chain-analysis`，判断已确认问题或强候选是否能组合成更高风险链路。
- 对已验证 finding 安排 evidence 复现和最终报告；UI 可见类 finding 需要原始截图和红框标注，纯 API/passive/协议类 finding 可用 selected request/response、HAR slice、flow fingerprint 和短响应 preview 作为等价证据。

主代理不直接执行漏洞利用逻辑，不把未触发漏洞 Skill 提前跑完。注册表之外的新方向只能进入 hypothesis queue 或低影响补充侦查；要成为正式测试任务，必须转成 observation 后匹配现有 Skill，或作为新增 Skill 建议记录。

## 自主度与假设队列

默认自主度为 `guided`。主代理可以在不突破 scope、速率限制和低影响原则的前提下主动补齐证据，但所有动作必须能解释为“确认观察信号”或“补齐已触发任务的必要 artifact”。

自主度分级：

- `conservative`：只按已注册 activation 派发；缺少 artifact 时记录 waiting，不做额外探测。
- `guided`：默认模式。允许对候选线索做有限补证，例如一次同源只读请求、一次 compact corpus-query、一次页面控件小范围探测、一次 API 文档可访问性确认。
- `aggressive_authorized`：仅在用户明确授权高自由度时使用。允许更宽的低速率枚举和多分支补证，但仍禁止破坏性动作、DoS、高频爆破、scope 外访问和未授权资源扩张。

`hypothesis_queue` 用来保存“合理但尚未能触发注册 Skill”的线索。每条 hypothesis 至少包含：

```json
{
  "id": "hyp-001",
  "title": "疑似 GraphQL 接口暴露",
  "source": "request_corpus",
  "evidence": ["evidence/corpus/request-corpus.jsonl#request-123"],
  "proposed_signal": "api_interface_candidate",
  "allowed_probe": "one_same-origin_readonly_request",
  "status": "pending|confirmed|dismissed|needs_new_skill"
}
```

确认规则：

- 低影响确认后能映射到现有 Skill 的，写入 observations 并重新计算队列。
- 不能映射到现有 Skill 但有价值的，写入 `next_actions` 和 `skill_ideas`，不临时创建未定义子代理。
- 缺少授权、需要写操作、需要高频请求或需要访问 scope 外目标的，直接记录为 `blocked`。

## 运行目录与只读源文件

主代理在任何侦查、浏览器、抓包、报告或子代理任务开始前，必须确定 `XSEC_RUN_ROOT`。如果用户没有指定，使用仓库下 `.xsec-runs/default/`。本文中的 `evidence/...`、`reports/...`、`tmp/...`、`tools/...`、`data/...` 都是 run-root 相对路径，不是 Skill 源目录相对路径。

Skill 源文件区域必须只读：`SKILL.md`、`references/`、`templates/`、`skills/` 不得作为输出目录。`templates/found-vulnerability.md` 和 `templates/not-found.md` 只能读取并渲染到 `reports/`，禁止原地替换占位符或覆盖模板文件。JWT 的 `rockyou.txt` 字典缓存是例外：它按设计保留在 `skills/xsec-jwt-security/wordlists/` 供后续复用。

## 初期侦查阶段

初期侦查是固定前置阶段，但仍然受速率限制和 traffic policy 约束。主代理应为每个侦查子代理分配独立 `agent`、高位随机 `proxy` 端口、`flow`、`evidence_dir` 和 `passive_findings` 路径，所有 HTTP(S) 流量都必须经过 browser traffic adapter 的 mitm proxy。端口由 Agent 手动选择，冲突时手动换另一个并同步更新该子代理所有命令和 payload。

推荐并行子代理：

- `site-profile-classifier`：读取 scout summary、headers、HTML/JS 短摘录、静态资源路径、响应扩展名、server header 和路由模式，输出 `site_profile`。
- `api-path-discovery`：从 browser scout、JS bundle 短摘录、source map 线索、forms/actions、request corpus 和 route-map 中提取 API base path、接口路径、认证 API 和文档路径。
- `login-surface-discovery`：归集登录框、密码字段、认证 API、后台/管理登录入口、DirSearch 发现的登录页面，并把每个登录面写成 observation。
- `dirsearch-webroot`：仅在站点画像允许时执行 Web 根路径 DirSearch。
- `dirsearch-api-paths`：对 API base path 或接口目录做 DirSearch；不因 Vue/React SPA 画像而跳过。

侦查输出必须写入 `evidence/recon/`，例如：

```text
evidence/recon/site-profile.json
evidence/recon/api-paths.json
evidence/recon/login-surfaces.json
evidence/recon/dirsearch-webroot.jsonl
evidence/recon/dirsearch-api-paths.jsonl
evidence/passive/scout-passive-findings.jsonl
```

## 站点画像与 DirSearch

`site-profile-classifier` 必须给出 `site_profile.kind`：

- `spa_template`：Vue、React、Angular、Vite、Webpack SPA、前后端分离静态站点等。默认不做 Web 根路径 DirSearch，避免对静态前端做低价值目录爆破。
- `server_script`：PHP、ASP/ASPX、JSP、ThinkPHP、Laravel、Struts、传统模板渲染、带脚本扩展路径或服务端模板错误特征。执行一次受控 Web 根路径 DirSearch。
- `unknown`：证据不足以判断。执行一次受控 Web 根路径 DirSearch。

DirSearch 约束：

- 只对目标 host、scheme、端口和 path 执行。
- 必须通过分配的 `--proxy http://127.0.0.1:<port>` 走 passive hook。
- 使用低影响、低速率、有限字典；不得递归到目标外，不做 DoS 式高并发。
- 发现 `admin`、`manager`、`backend`、`login`、`signin`、`auth`、`console`、`swagger`、`api-docs`、`backup`、`config`、`.env`、source map 等路径时，只记录 observation，由注册表触发相应 Skill。
- API DirSearch 只对 `api_base_paths`、接口目录或文档路径做，例如 `/api/`、`/api/v1/`、`/admin/api/`、`/swagger/`；不要把每个具体业务 endpoint 当作目录根反复扫描。

## 登录与凭据策略

- 如果用户提供测试账号密码，优先直接登录；登录成功后保存 `browser_state`，写入 `authenticated_session_obtained` 和 `post_login_surface_available`，再分配登录后漏洞 Skill。
- 如果未提供账号密码，但发现登录框、密码字段、认证 API 或 DirSearch 发现后台登录框，则按注册表启动弱口令测试。
- 如果弱口令成功，记录 issue 和 win，并用保存的 state 重新计算登录后测试队列。
- 如果登录入口有验证码、OTP、账号锁定或字典限制，弱口令子代理必须遵守测试边界；无法完成时返回 `blocked` 或 `not_found`，不要升级为未授权绕过或高频尝试。
- 弱口令测试按凭据审计预算执行，而不是默认大规模尝试。主代理应在 payload 中给出 `attempt_budget`、`max_threads`、`delay_seconds`、`lockout_stop_condition` 和允许的凭据来源。

## 场景 Playbook 与解锁

`config/vulnerability-skills.yaml` 的 `scenario_playbooks` 是主代理的预设路线图，用于理解“常见场景下哪些 Skill 可能被后续解锁”。它不是执行清单；正式子代理派发仍以每个 Skill 的 `activation.any_signals`、`requires_artifacts` 和 `requires_environment` 为准。无法匹配注册表的新线索只能进入 `hypothesis_queue`，按自主度策略做低影响确认。

主代理按以下方式使用 playbook：

- 公开面场景：只有目标 URL 且未登录时，先跑站点画像、API 发现、登录面归集、必要 DirSearch、传输层/版本/目录/API/中间件/未授权/客户端硬编码和 passive 复核类节点；未授权节点需要从 HTML/JS/前端配置中提取疑似后端 path 后做匿名最小化访问验证。
- 登录面场景：发现登录框、密码字段、认证 API 或后台登录入口后，才考虑弱口令、暴力破解防护、验证码/OTP 和后期用户名枚举。
- 登录后场景：用户提供凭据或弱口令成功后，写入 `authenticated_session_obtained`，再解锁浏览器存储、JWT、会话失效、权限边界、密码策略、密码明文返回、CSRF、CORS、SQL 注入、上传、下载和 XSS 等登录后节点。
- API 文档/接口场景：发现 API base path、Swagger/OpenAPI/Knife4j/WSDL，或从前端资产中提取到疑似后端 path 后，先做 API DirSearch/接口文档复核或未登录 path 拼接验证，再按结果解锁未授权、CORS、SQL 注入和登录后权限边界。
- 文件面场景：发现上传、下载、预览、导入导出或路径参数后，解锁上传安全、下载访问控制、路径遍历、XSS；如果上传初始化返回对象存储凭据，再解锁云密钥复核。
- AI 对话场景：只有发现聊天、RAG、流式模型或模型输出被前端渲染时，才解锁 LLM prompt security；若模型输出进入 HTML/富文本渲染，再追加 XSS。
- 敏感信息与 Shiro hook 场景：passive hook 或客户端分析命中 AK/SK、私钥、SQL 报错、详细错误、内网地址、Shiro rememberMe/deleteMe 后，按 `target_skill` 或信号解锁对应专项 Skill；这些命中是候选，不是最终漏洞。

每次子代理完成后，主代理读取其 `unlocks_on_success`、`observations`、`hypotheses` 和 `wins`，把新增信号写入 `status.json`，然后重新计算队列。若只满足 playbook 但缺少环境，例如没有登录态、没有测试手机号、没有 AI 对话框、没有文件上传控件，则该 Skill 保持 idle 或 blocked；若缺的是可低影响补齐的 compact artifact，可按当前自主度发起补证。

## Passive Hook 与敏感信息复核

passive hook 只负责自动落盘和标记，不直接生成漏洞结论。主代理在两个时机消费 passive findings：

- 测试过程中：把高价值命中转换成 observations，例如 `passive_secret_match`、`passive_sql_error_match`、`passive_detailed_error_match`、`passive_internal_ip_match`，用于触发对应 passive Skill。
- 收尾前：启动 `passive-sensitive-review` 子代理并读取 `skills/xsec-passive-scanning` 总入口，读取所有 `evidence/passive/*-passive-findings.jsonl`，按 `target_skill` 分组，去重同一 `match_hash + path + pattern_id`，再分配给对应 Skill 做最小化判断和报告生成。

passive review 子代理只能读取 JSONL 中的脱敏 preview、hash、路径、状态码、request id 和必要的短证据片段。需要证明时，通过 flow/request id 定位最小请求响应，不整读完整 flow 或完整响应体。

## 收尾组合漏洞分析

最终报告前，主代理必须尝试调用 `xsec-vulnerability-chain-analysis`。输入只包含已验证 issue、强候选、wins、登录态、被动敏感信息命中、API/DirSearch 发现、权限边界观察和报告路径。组合分析的目标是判断是否存在可闭合链路，例如：

- 信息泄露或默认凭据 -> 弱口令/有效登录态 -> 后台入口或敏感业务 API。
- API/目录暴露 -> 未授权访问 -> 内网/错误/配置泄露。
- 弱认证 -> 水平/垂直越权 -> 敏感数据访问或下载。
- 会话未失效、浏览器敏感存储、JWT 缺陷与越权问题叠加。

组合分析必须保持最小化验证，不为了证明影响而批量获取数据；如果链路无法闭合，应生成 not-found/blocked 结论，说明缺少哪一跳证据。

## 配置入口

读取：

- `config/vulnerability-skills.yaml`
- browser traffic adapter 的 `SKILL.md`
- 必要时读取 browser traffic adapter 的 preflight/runbook
- 派发子代理前按证据级别引用截图教程 `web-pentest-browser-flow/runbooks/05-evidence-browser.md` 和报告教程 `web-pentest-browser-flow/runbooks/06-report.md`

注册表里的 `orchestration_model` 定义状态账本和子代理 payload 契约；`autonomy` 定义低影响补证边界；`scenario_playbooks` 定义常见场景下的解锁路线；`recon` 定义测试初期固定侦查任务；`vulnerability_skills` 定义由 observations 触发的漏洞测试；`post_processors` 定义收尾复核任务。`priority` 只在多个 Skill 已经满足 activation 时排序；没有满足 activation 或环境门槛的 Skill 保持 idle/blocked。`status: not_installed` 或 `enabled: false` 的条目只能进入建议或等待状态，不能启动子代理。

## 工作流

1. 确认测试目标 URL。
2. 确定并导出 `XSEC_RUN_ROOT`，确认它不位于 `skills/`、`templates/` 或 `references/` 下。
3. 读取 `config/vulnerability-skills.yaml`，加载 `scheduler`、`orchestration_model`、`autonomy`、`scenario_playbooks`、`adapters`、`recon`、`vulnerability_skills` 和 `post_processors`。
4. 手动选择高位随机端口并启动 scout 代理和 mitm proxy；确认 `mitm-start` 输出包含 `passive_findings`，后续所有浏览器动作、DirSearch、弱口令和验证流量都使用分配的 proxy。若端口占用或启动失败，Agent 手动更换端口并同步更新 payload。
5. 并行启动初期侦查子代理：`site-profile-classifier`、`api-path-discovery`、`login-surface-discovery`，以及按站点画像条件触发的 `dirsearch-webroot`。
6. 对 API 路径发现结果执行 `dirsearch-api-paths`：只对已归一化、目标的 API base path 或接口目录做受控 DirSearch。
7. 调用 browser traffic adapter 做基线 scout，获取 routes、forms、actions、API delta、session 信号、frontend asset inventory、匿名响应样本和 passive findings path。
8. 如果用户提供了测试账号密码，直接使用 browser traffic adapter 登录、保存 browser state，并写入 `authenticated_session_obtained`；若没有凭据但发现登录框/认证 API，则按 activation 启动弱口令测试。
9. 将 scout、DirSearch、API discovery、登录结果和 passive hook 命中转成 observations，并写入 `evidence/orchestrator/status.json`。若在 HTML、JS、前端配置或请求语料中用 `pathRegex = /['"]\/[^/][^>< \)\(\{\}]*?['"]/g` 提取到疑似后端接口 path，同时能定位同源或 API host，写入 `frontend_endpoint_path_candidate_detected`，并保存候选到 `evidence/recon/frontend-endpoint-paths.json`。
10. 用 observations 匹配每个漏洞 Skill 的 `activation.any_signals`，再检查 `requires_artifacts`、`requires_environment`、全局阻断信号和 scope；无法匹配的合理线索写入 hypothesis queue。
11. 只为满足 activation、enabled、artifact、environment 四类条件的漏洞 Skill 创建子代理任务；不满足时记录 `idle`、`waiting_for_artifact` 或 `blocked` 原因。若当前自主度允许且缺口可低影响补齐，先补证再重新计算。
12. 子代理返回后，更新 `issues`、`not_found`、`wins`、`observations`、`active_tasks`、`queued_tasks`、`report_index` 和 `next_actions`，并把 `unlocks_on_success` 对应的新信号写回状态账本。
13. 每次状态变化后输出简短实时总结。
14. 对每个 `validated` 或即将写入 found 报告的 finding，按证据级别复现：UI 可见类先读取 `web-pentest-browser-flow/runbooks/05-evidence-browser.md`，保存原始截图、HAR、selected request/response 和控制台错误，并生成红框标注截图；纯 API/passive/协议类至少保存 selected request/response、HAR slice 或 flow fingerprint，并在报告中写明无法截图原因。
15. 队列收敛前运行 passive findings 复核子代理，把敏感信息命中分配给对应 passive Skill 生成报告。
16. 最后调用漏洞组合 Skill，对已验证 issue、wins、敏感信息命中、弱口令、越权、会话、API 暴露等做组合链分析。
17. 队列为空或达到收敛条件后输出最终报告和 evidence pack。

## 事件触发模型

漏洞 Skill 由观察信号激活，而不是默认全量运行。每次 scout、act、flow-normalize、子代理返回后，都重新计算触发队列。

| 观察信号 | 触发动作 |
| --- | --- |
| `site_profile.kind=server_script` 或 `site_profile.kind=unknown` | 启动一次受控 Web 根路径 DirSearch；所有流量走 proxy/passive hook |
| `site_profile.kind=spa_template` | 跳过 Web 根路径 DirSearch；继续 API 路径发现和 API DirSearch |
| 发现 API base path、接口目录、Swagger/OpenAPI/Knife4j/WSDL | 对 API 路径做受控 DirSearch；按结果解锁 `api-interface-exposure`、`unauth-access`、`cors-misconfiguration`、`sql-injection`，有登录态时再看 `access-control-idor` |
| 从 HTML、JS、前端配置或请求语料中提取到疑似后端 path，且能定位 API host 或同源 host | 记录 `frontend_endpoint_path_candidate_detected`，启动 `unauth-access` 做未登录 path 拼接、低影响参数补全和匿名读取验证 |
| 发现登录框、密码字段、认证 API | 按环境门槛解锁 `weak-pass-check`、`brute-force-protection`、`captcha-otp-defect`；用户名枚举默认放后期 |
| DirSearch 发现后台、管理端、console、admin login 等登录框 | 记录 `admin_login_form_detected`，解锁登录面测试和 `middleware-unauth-management`/`unauth-access` 的最小化复核 |
| 用户提供测试账号密码且登录成功 | 保存 browser state，记录 `authenticated_session_obtained` 和 `post_login_surface_available`，直接重新计算登录后漏洞 Skill |
| 弱口令验证成功、获得 session、保存 browser state | 记录到 `issues` 和 `wins`；把 `authenticated_session_obtained` 写入 observations；重新计算登录后漏洞 Skill |
| 发现多角色账号、用户切换入口、ID 型资源路径、403/401 边界 | 如果环境满足，启动 `access-control-idor`、`file-download-access-control` 或登录后的 `unauth-access` 对照验证 |
| 登录后发现 Cookie、JWT、Bearer Token、rememberMe、浏览器存储 | 解锁 `browser-sensitive-storage`、`jwt-security`、`session-token-invalidation`、`cookie-security-flags`、`insecure-crypto` |
| passive hook 在 Cookie 头中发现 `rememberMe` 或 `deleteMe` | 记录 `passive_shiro_cookie_detected`；只有该信号存在时才解锁 `shiro-attack-detection`，先验证 Shiro 弱 Key，弱 Key 命中且授权允许时再做低影响利用链检测 |
| 发现注册、改密、重置、首次登录改密、管理员创建用户 | 解锁 `password-policy`、`password-storage-return`、`session-token-invalidation`；涉及验证码/OTP 时解锁 `captcha-otp-defect` |
| API 返回客户、订单、用户、手机号、邮箱、证件号等敏感字段 | 记录 `sensitive_data_exposure_candidate`；有对象 ID/角色边界时解锁 `access-control-idor`，有 CORS 头时解锁 `cors-misconfiguration` |
| 发现上传控件、上传 API、对象存储直传凭据 | 解锁 `file-upload-security`；上传后 URL/文件名回显再解锁 `file-download-access-control`、`xss`、`path-traversal` 或 `cloud-secret-leakage` |
| 发现下载、预览、导出、附件 ID、签名 URL、路径参数 | 解锁 `file-download-access-control`、`path-traversal`；如果是登录后对象资源，同时解锁 `access-control-idor` |
| 发现搜索/筛选/分页/排序/报表/详情等带参数请求 | 解锁 `sql-injection`；若 passive hook 先命中 SQL 报错，先由 `sql-error-info-leak` 复核并再解锁 SQL 注入 |
| 发现 URL 代取、Webhook、回调、远程图片/文件导入、预览外链 | 解锁 `ssrf`；只有具备回连监听或测试目标时才派发 |
| 发现 AI 对话、RAG、流式模型接口、模型输出进入前端渲染 | 解锁 `llm-prompt-security`；若模型输出被 HTML/富文本解释，再解锁 `xss` |
| 发现 CORS 头、Origin 反射、ACAC=true、跨站可读迹象 | 解锁 `cors-misconfiguration`；需要受控测试 Origin 和敏感响应对照 |
| 发现状态变更表单/API 且依赖 Cookie 会话 | 解锁 `csrf-protection-missing`；必须有可逆低影响动作和受控跨站页面 |
| 发现 HTTP 明文、弱 TLS、混合内容、Secure Cookie 缺失 | 解锁 `transport-security`，并为 Cookie/会话/密码传输类 finding 提供影响上下文 |
| 发现版本头、默认页、框架版本、组件版本 | 解锁 `version-info-exposure`；若版本指向管理端或配置端，再解锁对应专项 |
| 发现 source map、JS 配置、硬编码密钥、客户端包、前端路由清单 | 解锁 `client-hardcoded-secret`；输出的 AK/SK、内部地址、API path 再继续解锁云密钥、内网泄露、API 暴露等节点 |
| DirSearch 或 passive 发现 `.env`、备份包、Git/SVN、数据库备份、配置文件 | 解锁 `config-backup-leakage`；其中的凭据/内网/API/源码线索继续解锁下游节点 |
| 发现目录索引、敏感目录、对象存储清单、静态目录暴露 | 解锁 `directory-sensitive-leakage`；如果目录里出现配置/备份/源码，再解锁对应专项 |
| 发现堆栈、绝对路径、详细错误、默认错误页 | 解锁 `error-path-leakage`；若包含 SQL/ORM 关键字，再解锁 `sql-error-info-leak` 或 `sql-injection` |
| passive hook 命中秘钥、SQL 报错、详细错误、路径、内网 IP 或 Shiro Cookie | 收尾前先由 `passive-scanning` 分组；再启动 `cloud-secret-leakage`、`sql-error-info-leak`、`error-path-leakage`、`internal-network-leakage`、`shiro-attack-detection` 等专项 |
| 出现两个以上已验证 issue、一个 issue 加关键 win、或 passive 命中可作为前置条件 | 收尾时启动漏洞组合 Skill，判断是否能闭合风险链路 |

触发前检查四件事：漏洞 Skill 已注册且 enabled、当前信号满足 activation 条件、必需 artifacts 存在、`requires_environment` 描述的环境真实存在。任一条件不满足时，先判断是否可按 `autonomy` 做低影响补证；不可补证时只记录为 observation、hypothesis、idle、waiting 或 blocked，不启动子代理。

## 状态账本

实时状态写到 `evidence/orchestrator/status.json`，每次重大转移后更新：

```json
{
  "ok": true,
  "phase": "post_login",
  "recon": {
    "site_profile": {"kind": "server_script", "confidence": "medium", "evidence": "evidence/recon/site-profile.json"},
    "api_paths": "evidence/recon/api-paths.json",
    "frontend_asset_inventory": "evidence/recon/frontend-assets.json",
    "frontend_endpoint_paths": "evidence/recon/frontend-endpoint-paths.json",
    "anonymous_response": "evidence/recon/anonymous-response.json",
    "login_surfaces": "evidence/recon/login-surfaces.json",
    "dirsearch": {
      "webroot": "evidence/recon/dirsearch-webroot.jsonl",
      "api_paths": "evidence/recon/dirsearch-api-paths.jsonl"
    },
    "passive_findings": [
      "evidence/passive/scout-passive-findings.jsonl"
    ]
  },
  "progress": [
    {"time": "2026-06-04T10:00:00+08:00", "event": "scout_completed", "summary": "发现 1 个登录框和 8 个 API endpoint"}
  ],
  "observations": [
    {"id": "obs-001", "signal": "login_form_detected", "source": "forms.json", "evidence": "evidence/browser/scout.summary.json"},
    {"id": "obs-002", "signal": "passive_sql_error_match", "source": "passive-hook", "evidence": "evidence/passive/scout-passive-findings.jsonl"}
  ],
  "hypothesis_queue": [
    {
      "id": "hyp-001",
      "title": "疑似 GraphQL 接口暴露",
      "source": "request_corpus",
      "evidence": ["evidence/corpus/request-corpus.jsonl#request-123"],
      "proposed_signal": "api_interface_candidate",
      "allowed_probe": "one_same-origin_readonly_request",
      "status": "pending"
    }
  ],
  "active_tasks": [
    {"agent": "weak-pass-check", "vulnerability_skill_id": "weak-pass-check", "status": "running"}
  ],
  "queued_tasks": [],
  "issues": [
    {
      "id": "issue-001",
      "severity": "high",
      "title": "弱口令登录成功",
      "status": "validated",
      "evidence": ["evidence/agents/weak-pass-check/findings/finding-001"],
      "report": "reports/测试系统/弱口令登录成功.md",
      "raw_screenshots": ["reports/测试系统/弱口令登录成功.assets/原始截图.png"],
      "annotated_screenshots": ["reports/测试系统/弱口令登录成功.assets/证据截图.png"],
      "evidence_level": "ui_screenshot"
    }
  ],
  "not_found": [
    {"id": "not-found-001", "title": "默认密码未命中", "status": "not_found", "reason": "测试字典内未发现可用默认凭据", "report": "reports/测试系统/not-found/默认密码未命中.md"}
  ],
  "wins": [
    {"id": "win-001", "title": "获得测试账号有效 session", "impact": "可进入登录后功能区", "unlocks": ["browser-sensitive-storage", "jwt-security", "session-token-invalidation", "access-control-idor"]}
  ],
  "next_actions": [
    "使用保存的 browser state 对登录后 API 做权限边界测试"
  ],
  "report_index": {
    "system_name": "测试系统",
    "found": ["reports/测试系统/弱口令登录成功.md"],
    "not_found": ["reports/测试系统/not-found/默认密码未命中.md"]
  }
}
```

`issues` 只记录已验证或有明确证据支撑的问题。每条 issue 的详情文档必须包含 Burp Raw 风格请求/响应数据包；UI 可见类问题还必须包含关键证据截图，API/passive/协议类问题必须包含 selected request/response、HAR slice、flow fingerprint 或 corpus-query 证据路径，并写出 `screenshot_unavailable_reason`。`hypothesis_queue` 记录尚未转成正式 observation 的新方向。`not_found` 记录已完成验证但未发现漏洞的原因，并尽量引用状态截图或等价证据。`wins` 记录测试进展，例如获得 session、进入后台、发现关键 API。每条记录都必须引用 evidence path、screenshot path 或 Markdown report path。

## 子代理任务 payload

每个子代理只执行一个漏洞 Skill。主代理发送的 payload 应包含：

```json
{
  "agent": "weak-pass-check",
  "system_name": "测试系统",
  "orchestrator_subagent_reference": "references/vulnerability-subagent.md",
  "vulnerability_skill": {
    "id": "weak-pass-check",
    "path": "skills/weak-pass-check",
    "source_repo": "https://github.com/xsec-labs/x-sec-agent.git"
  },
  "browser_traffic_adapter": {
    "id": "web-pentest-browser-flow",
    "path": "web-pentest-browser-flow",
    "reference": "web-pentest-browser-flow/references/subagent-browser-operator.md"
  },
  "evidence_runbook": "web-pentest-browser-flow/runbooks/05-evidence-browser.md",
  "report_runbook": "web-pentest-browser-flow/runbooks/06-report.md",
  "autonomy": {
    "level": "guided",
    "allowed_supplemental_probes": [
      "one_same-origin_readonly_request",
      "compact_corpus_query",
      "small_visible_control_probe"
    ],
    "max_supplemental_requests": 3
  },
  "deliverables": {
    "evidence_level": "ui_screenshot",
    "screenshot_required": true,
    "equivalent_evidence_allowed": true,
    "must_read_evidence_runbook_before_report": true,
    "found": {
      "raw_screenshot": "reports/<系统名称>/<漏洞名称>.assets/原始截图.png",
      "annotated_screenshot": "reports/<系统名称>/<漏洞名称>.assets/证据截图.png",
      "selected_request_response": "evidence/agents/<agent>/selected-request-response.http",
      "flow_fingerprint": "evidence/agents/<agent>/flow-fingerprint.json",
      "markdown_report": "reports/<系统名称>/<漏洞名称>.md",
      "burp_raw_packets_required": true
    },
    "not_found": {
      "status_screenshot": "reports/<系统名称>/not-found/<漏洞名称>.assets/状态截图.png",
      "markdown_report": "reports/<系统名称>/not-found/<漏洞名称>.md"
    }
  },
  "activation_reason": "login_form_detected",
  "target": "https://test.example.com",
  "proxy": "http://127.0.0.1:<random_high_port>",
  "flow": "evidence/flows/weak-pass-check.flows",
  "passive_findings": "evidence/passive/weak-pass-check-passive-findings.jsonl",
  "evidence_dir": "evidence/agents/weak-pass-check",
  "browser_state": "evidence/agents/weak-pass-check/state.json",
  "inputs": {
    "observations": ["obs-001"],
    "artifacts": [
      "evidence/browser/scout.summary.json",
      "evidence/corpus/api-inventory.json",
      "evidence/recon/site-profile.json",
      "evidence/recon/api-paths.json",
      "evidence/passive/scout-passive-findings.jsonl"
    ]
  },
  "constraints": [
    "只执行分配到的漏洞 Skill",
    "所有浏览器、DirSearch、弱口令和验证流量都必须经过分配的 proxy/passive hook",
    "UI 可见类 finding 报告前必须读取 evidence_runbook，并按截图教程保存取证截图",
    "纯 API/passive/协议类 finding 可使用 selected request/response、HAR slice、flow fingerprint 或 corpus-query 命中片段作为等价证据",
    "真实发现漏洞后生成 reports/<系统名称>/<漏洞名称>.md；UI 证据截图保存到对应 .assets 目录",
    "validated issue 必须返回 annotated_screenshots 或 screenshot_unavailable_reason 加等价 evidence path",
    "漏洞详情文档必须使用 Burp Raw 风格展示关键请求和响应数据包",
    "未发现漏洞时生成 reports/<系统名称>/not-found/<漏洞名称>.md 并写清楚原因",
    "未发现结果优先保存状态截图；无法截图时返回覆盖范围证据路径",
    "只返回 compact JSON、finding candidates、validated issues、not_found、hypotheses、wins、evidence paths 和 report paths"
  ]
}
```

如果运行中的任务达到 `scheduler.max_concurrent_subagents`，把新触发任务放入 waiting queue。任务完成、失败或取消后再补位。队列按 `priority`、触发时间和风险解锁价值排序。

## 实时总结

每次阶段变化、子代理启动/完成、finding 变为 validated、战果解锁后，都输出简短进度：

```text
当前阶段：post_login
侦查：站点画像 server_script，Web 根路径 DirSearch 已完成，API 路径 DirSearch 已完成
已发现：登录框 1 个，后台登录入口 1 个，认证 API 2 个，客户信息 API 1 个
被动命中：SQL 报错 1 条，内网 IP 2 条，已分配 passive Skill 复核
进行中：weak-pass-check 已完成；access-control-idor 等待第二账号或 ID 型资源证据
问题清单：issue-001 弱口令登录成功 high
未发现：not-found-001 默认密码未命中，原因已写入 not-found 文档
战果：win-001 已获得有效 session，可用于后续浏览器存储、JWT、会话失效和权限边界测试
报告：found 1 份，not-found 1 份
下一步：用保存的 state 执行已注册的登录后漏洞 Skill；收尾前调用漏洞组合 Skill
```

总结要区分已验证问题、普通观察和下一步假设。不要把未经验证的风险写成已确认漏洞。

## 收敛条件

满足任一条件时停止启动新子代理，只做汇总和报告：

- 速率、账号或时间预算达到限制。
- 没有新的 observations 能触发 enabled 漏洞 Skill。
- 所有 triggered tasks 都已完成且没有待复现 finding。
- 目标进入 challenge/阻断状态，需要用户提供测试目标或人工处理。
- 用户要求停止、暂停或只输出当前状态。
