# 主 Agent 编排指南（树状 · MCP 管理）

先读 [运行边界与证据口径](security-boundaries.md)，本文所有操作受该边界约束。`SKILL.md` 已写明的工具清单（含 `xsec_tree_*` 别名）、浏览器接管、子 Agent 派发登记顺序和证据分级，本文不再重复。

主 Agent 负责判断、调度和接住产出，不负责具体漏洞怎么测。用 MCP 持有一棵**树状测试任务**：按观察信号建节点、派发子 Agent、维护进度与战果。

## 原则：给目标和边界，不给死步骤

本文的流程、清单、触发规则都是**参考路径**。主 Agent 像有经验的测试负责人一样自主决定先做什么、跳过什么、追加什么。

- 判断测试价值是主 Agent 的权力：有价值、现在能测、能产出结论才建节点；价值低或环境不满足的跳过或标 waiting，不机械地“不满足就 skipped”。
- 路由索引和注册表是派发主路径，不是天花板。注册表之外的合理线索：记 hypothesis，做低影响确认，再决定建节点或建议新增 Skill。
- 派发 payload 写清“测什么漏洞、为什么派你（`activation_reason`）、目标、可用上下文、硬边界”，不写“第一步做 X”。上下文给足：共享发现 fingerprint、artifact 路径、已验证 issue、登录态、测试账号。
- 信任子 Agent 在边界内自主探索；主 Agent 只看结果：节点结论、共享发现回填、证据质量。子 Agent 回填的新信号、hypothesis 要主动读、主动建新节点。
- 没有依赖关系的节点并行派发；登录后才能测的等前置完成。运行中子 Agent 达到 `scheduler.max_concurrent_subagents` 时，新节点放入 waiting，有任务结束后补位；多个 Skill 同时满足时按路由索引顺序（`priority`）。
- 请求量、并发和时间遵守已批准上限，达到预算、风控或服务异常停止条件即停止相关动作。遵守低影响、最少信息披露、禁止破坏性/DoS、证据真实性和源目录只读；`scope_policy` 只做资产归因，不是访问边界。
- 主 Agent 一般不亲自做漏洞利用，但简单、低风险、能快速确认信号的小验证可以自己做。

## 树与共享状态

MCP 里的树和共享发现是**权威状态**，桌面端「测试树」实时可视化；`evidence/orchestrator/status.json` 只是可选的人类可读镜像（字段对应节点/发现/issues/not_found/wins），派发决策以 MCP 为准。`issues` 只记已验证或有明确证据的问题，每条引用 evidence/screenshot/report 路径或 shared_finding fingerprint。

- 更新或删除树节点时按 `SKILL.md` 的并发更新规则带 `expectedRevision`（assignment 作用域，任务内任何写入都会让它递增）；被拒绝就重新 `attack_path_list` 取最新状态再试，不要覆盖别的 Agent 刚写的结论。
- 收回失控或超预算的子 Agent：`xsec_subagent_cancel(subagent_id, reason)`。子 Agent 运行期间自己定期调 `xsec_subagent_heartbeat`（任何已认证 MCP 调用也会续期），终态只能由它自己调用 `xsec_subagent_complete(status, conclusion)` 提交，`status` 取 `done`/`vuln`/`failed`/`cancelled`（测了没发现也是 `done`，在 `conclusion` 说明）；主 Agent 用 `xsec_subagent_status` + `attack_path_list` 轮询。

## 分层建树（parent_id 语义）

**树的层级 = 执行/依赖顺序，不是把所有节点平铺在 root 下。** 每次 `attack_path_node_create` 都要想清楚父节点是谁。把所有节点的 `parentId` 填 root 会得到只有两层的树，看不出执行顺序，也表达不了“往下继续链接下一层利用”——禁止。

**阶段骨架层**（root 的直接子节点，`kind="phase"`，用到才建）：`recon` 侦查、`pre-auth` 未登录面、`auth` 凭据获取、`post-auth` 登录后、`surface-specific` 专项面（文件/AI/SSRF 等）、`passive-review` 被动复核、`chain-analysis` 组合链。

**parent_id 选择规则**（每次建节点走一遍）：

1. 阶段骨架节点 → `parent_id` = root。
2. 某阶段里新的、独立的测试面（无单一上游触发点）→ 该阶段骨架节点。
3. 由另一个测试节点的结果直接解锁或触发 → 那个上游测试节点，往下嵌套；子 Agent 回填新发现后建的新节点，挂在回填它的那个节点下。
4. 跨阶段推进用阶段切换表达（新节点挂新阶段骨架）；同一条利用链内逐层深入用父子嵌套表达。

```
root: <目标>
├─ recon (phase): site-profile / api-path-discovery / login-surface
├─ pre-auth (phase)
│   ├─ transport-security
│   └─ unauth-access
│        └─ internal-network-leakage      ← 由未授权访问结果解锁
├─ auth (phase)
│   └─ weak-pass-check                     ← 由 login-surface 解锁
├─ post-auth (phase)                       ← 由登录成功解锁
│   ├─ jwt-security
│   └─ access-control-idor
│        └─ （敏感数据访问）               ← 由越权结果解锁
└─ chain-analysis (phase)
```

如果 weak-pass / transport-security / unauth-access / cookie 等节点都是 root 的平级子节点，就是错误的平铺，要改成按执行顺序分层。

## 流程（建议路径，按目标自主调整）

1. 确认目标 URL、账号和速率限制；确定并导出 `XSEC_RUN_ROOT`（未指定用 `.xsec-runs/default/`；`evidence/`、`reports/`、`tmp/` 相对它）。`SKILL.md`、`references/`、`templates/`、`skills/`、`config/` 只读，不当输出目录；`templates/*.md` 只读，渲染到 `reports/`；JWT 的 `rockyou.txt` 字典缓存是例外。
2. 读 [路由索引](routing-index.md)（信号 → Skill 一行一个）。只有要看某个 Skill 的 `requires_environment`、`requires_artifacts`、`blocked_when`，或 `scenario_playbooks`、`autonomy`、`orchestration_model` 时，才读 `config/vulnerability-skills.yaml` 的对应片段，不要整份通读。
3. `attack_path_node_create(title="root", kind="root")` 建根，再按需建阶段骨架节点。
4. 基线 scout：用 MCP 浏览器访问目标并看 network，把 forms、actions、routes、API 线索、登录入口、报错、版本、疑似凭据写入 `attack_path_finding_add`。从前端语料提取到疑似后端 path 或任意 API host 时写 `frontend_endpoint_path_candidate_detected`，跨域或跨 host 不影响继续验证。
5. 按需派侦查子 Agent（见下节），每个有独立 `page_group_id` 和 `evidence_dir`，发现统一写共享发现库。
6. 用户给了账号密码就直接用共享浏览器登录，写 `authenticated_session_obtained`、`post_login_surface_available`，不必以弱口令测试作前置；没给但发现登录框/认证 API，建 `weak-pass-check` 节点。
7. 用共享发现匹配路由索引的信号，检查 artifact、环境和阻断信号；对满足条件的信号建节点（`parentId` 按上节规则）→ `xsec_subagent_dispatch(node_id, browser_session_id)` → 按 `SKILL.md` 的登记协议启动子 Agent。环境不满足时自行判断：补一次低影响证据凑齐、标 waiting，或自己做简单验证。无法匹配的合理线索进 hypothesis。
8. 子 Agent 返回后读 `attack_path_list` + `attack_path_findings_list`，把新信号建成新节点继续长树；前一个节点的战果只解锁后续节点，不等于后续已是确认漏洞。每次状态变化输出一段简短总结。
9. 队列收敛前做收尾（见下）；队列为空或满足收敛条件后 `xsec_report_submit` 出最终报告和 evidence pack。

## 初期侦查与 DirSearch

初期侦查是建议的前置阶段，页面访问和被动流量观察走 MCP 浏览器 + network；DirSearch 的批量路径探测走系统终端（见下），不逐条经浏览器模拟。推荐的侦查子 Agent（可增减）：

- `site-profile-classifier`：读 headers、HTML/JS 短摘录、静态资源路径、server header、路由模式，输出 `site_profile.kind`。
- `api-path-discovery`：从 JS 短摘录、source map、forms/actions、请求语料、route-map 提取 API base path、接口路径、认证 API、文档路径。
- `login-surface-discovery`：归集登录框、密码字段、认证 API、后台登录入口。
- `dirsearch-webroot` / `dirsearch-api-paths`：见下。

产物写 `evidence/recon/`（`site-profile.json`、`api-paths.json`、`login-surfaces.json`、`dirsearch-*.jsonl`），高价值命中同时 `attack_path_finding_add`。

DirSearch：`server_script` 和 `unknown` 站点执行一次受控 Web 根路径 DirSearch；`spa_template` 通常跳过，但判断前端可能有隐藏路由或配置文件时可自行跑一轮；API DirSearch 对 base path 或文档路径做，不因 SPA 跳过。路径探测本身用系统终端 MCP 执行（`terminal_open` 起一个 Shell 跑 dirsearch 类工具，`terminal_write` 送命令，`terminal_read` 分页取结果），不逐条经 MCP 浏览器模拟请求；参数、速率和字典范围见 `dirsearch_policy`。覆盖本节点分配的 host/scheme/端口/path，页面里自然发现的 HTTP(S) 目标记录来源后可继续；低影响、低速率、有限字典。命中 `admin`、`backend`、`login`、`swagger`、`api-docs`、`backup`、`config`、`.env`、source map 等路径时先 `attack_path_finding_add` 记录，再用 MCP 浏览器单独访问一次高价值命中确认响应内容（必要时截图或触发 passive 落盘），并判断是否建节点；新发现的 host 记录来源和资产归因，不因 `in_scope=false` 停止。

## 登录与凭据

- 弱口令按全量凭据审计执行：payload 给出 `max_threads`、`delay_seconds`、`lockout_stop_condition` 和允许的凭据来源；默认对选定字典全量尝试，命中即停。
- 登录入口有验证码/OTP/账号锁定/字典限制时子 Agent 遵守边界；无法完成就以 `done` 提交并在 `conclusion` 写明受阻原因，不升级为未授权绕过或高频尝试。
- 弱口令成功记 issue/win，用共享登录态重新计算登录后队列。

## 自主度与假设队列

档位不改变已批准的上限，也不改变 `scope_policy` 只做归因的口径：`conservative` 只按已注册 activation 派发，缺 artifact 记 waiting；`guided`（默认）允许有限补证，如一次自然发现目标的只读请求、一次页面控件小范围探测、一次 API 文档可访问性确认；`aggressive` 允许更宽的低速率枚举和多分支补证，仍禁止破坏性动作和 DoS。

`hypothesis_queue` 存“合理但尚未触发注册 Skill”的线索，每条含 `id`、`title`、`source`、`evidence`（fingerprint）、`proposed_signal`、`allowed_probe`、`status`（`pending|confirmed|dismissed|needs_new_skill`）。能映射到现有 Skill 的建节点并派发；有价值但无对应 Skill 的，自行判断记 `next_actions`/`skill_ideas`、做低影响验证或标 `blocked`；需写操作或高频请求的按风险自行决定。

## 触发判断

路由索引给出“信号 → Skill”。除索引之外，这些关系需要主 Agent 自己记住：

- 前后端跨域不构成阻断；`frontend_endpoint_path_candidate_detected` 先启动 `unauth-access` 做未登录 path 拼接、低影响参数补全和匿名读取验证。
- DirSearch 发现后台/console/admin login 时记 `admin_login_form_detected`，解锁登录面测试和 `middleware-unauth-management`/`unauth-access` 的最小化复核。
- 用户名枚举默认放后期。发现多角色账号、用户切换入口、ID 型资源路径、403/401 边界时，环境满足再启动 `access-control-idor`、`file-download-access-control` 或登录后 `unauth-access` 对照。
- Cookie 里出现 `rememberMe`/`deleteMe`（`passive_shiro_cookie_detected`）是 `shiro-attack-detection` 最常见的触发信号，但不是前置门槛；技术栈判断目标可能是 Java + Shiro，或用户直接要求测试 Shiro 时，没有该 Cookie 命中也可以派发。真正的技术依赖在 skill 内部：先验证弱 Key，命中再做低影响利用链检测。
- 先命中 SQL 报错时，先由 `sql-error-info-leak` 复核再解锁 `sql-injection`；`ssrf` 只有具备回连监听或测试目标才派发；`csrf-protection-missing` 需要可逆低影响动作和受控跨站页面；`cors-misconfiguration` 需要受控测试 Origin 和敏感响应对照。
- API 返回客户/订单/用户/手机号/邮箱/证件号等敏感字段时记 `sensitive_data_exposure_candidate`；有对象 ID/角色边界解锁 `access-control-idor`，有 CORS 头解锁 `cors-misconfiguration`。
- 文件面：上传初始化返回对象存储凭据时再解锁 `cloud-secret-leakage`；上传后 URL/文件名回显再解锁下载、`xss`、`path-traversal`。AI 对话面：模型输出进入 HTML/富文本渲染再追加 `xss`。
- 版本头指向管理端/配置端、配置/备份/源码出现在目录里，要继续解锁对应专项；`client-hardcoded-secret` 输出的 AK/SK、内部地址、API path 继续解锁云密钥、内网泄露、API 暴露。
- `scenario_playbooks` 只是路线提示，派发以每个 Skill 的 `activation` 为准。只满足 playbook 但缺环境（无登录态、无测试手机号、无 AI 对话框、无上传控件）时节点保持 idle/blocked。

场景路线（`scenario_playbooks` 的摘要，只是路线提示，不是执行清单）：

- 公开面（只有目标 URL、未登录）：站点画像、API 发现、登录面归集、必要 DirSearch，再到传输层/版本/目录/API/中间件/未授权/客户端硬编码和 passive 复核。
- 登录面：发现登录框/密码字段/认证 API/后台登录入口后，才考虑弱口令、暴力破解防护、验证码/OTP、后期用户名枚举。
- 登录后：提供凭据或弱口令成功后，写 `authenticated_session_obtained`，解锁浏览器存储、JWT、会话失效、权限边界、密码策略、密码明文返回、CSRF、CORS、SQL 注入、上传、下载、XSS。
- API 文档/接口：发现 API base path、Swagger/OpenAPI/Knife4j/WSDL 或前端提取的后端 path 后，先做 API DirSearch/文档复核或未登录 path 拼接验证，再按结果解锁未授权、CORS、SQL 注入、登录后权限边界。
- 文件面：上传/下载/预览/导入导出/路径参数解锁上传安全、下载访问控制、路径遍历、XSS。AI 对话面：聊天/RAG/流式模型解锁 LLM prompt security。
- 敏感信息与 Shiro：抓包或客户端分析命中 AK/SK、私钥、SQL 报错、详细错误、内网地址、Shiro Cookie 后，按 `target_skill` 或信号解锁对应专项；这些命中是候选，不是最终漏洞。

每次子 Agent 完成后，读它回填的共享发现与节点结论，把新增信号建成新节点，重新计算队列。

派发前核对四件事：Skill 已注册且 enabled、信号满足 activation、必需 artifacts 存在、`requires_environment` 描述的环境真实存在；`status: not_installed` 或 `enabled: false` 的只能进建议/等待，不派子 Agent。

## 收尾

network 命中只负责标记，不直接生成漏洞结论。测试过程中把高价值命中（`passive_secret_match`、`passive_sql_error_match`、`passive_detailed_error_match`、`passive_internal_ip_match`）转成新节点；收尾前顺序如下，顺序可按实际调整：

1. 派 `passive-sensitive-review` 子 Agent（读 `skills/xsec-passive-scanning`）遍历敏感命中，按 `target_skill` 分组去重，分配给对应专项做最小化判断和报告；只读任务需要的证据，保留原始值只选最小片段。
2. 最终报告前必须尝试 `xsec-vulnerability-chain-analysis`，输入只含已验证 issue、强候选、wins、登录态、敏感命中、API/DirSearch 发现、权限边界观察。判断能否闭合链路（信息泄露→弱口令→后台；API/目录暴露→未授权→内网/配置泄露；弱认证→越权→敏感数据；会话/存储/JWT 缺陷叠加越权）；链路无法闭合时写 not-found/blocked 结论，说明缺哪一跳。
3. `xsec_report_submit`。

验收 `validated` 报告时按 `SKILL.md` 的证据分级要求核对：可复现证据链、关键截图或等价证据、触发条件和影响。

## 子 Agent 任务 payload

每个子 Agent 只执行**一个节点 + 一个漏洞 Skill**。`vulnerability_skill.path` 取自路由索引（`skills/<目录名>`）。

```json
{
  "role": "sub",
  "node_id": "<tree node id>",
  "subagent_id": "<xsec_subagent_dispatch 返回>",
  "page_group_id": "<xsec_subagent_dispatch 返回>",
  "browser_session_id": "<共享浏览器会话>",
  "agent": "weak-pass-check",
  "system_name": "测试系统",
  "orchestrator_subagent_reference": "references/vulnerability-subagent.md",
  "vulnerability_skill": {"id": "weak-pass-check", "path": "skills/weak-pass-check", "source_repo": "https://github.com/xsec-labs/x-sec-agent.git"},
  "activation_reason": "login_form_detected",
  "target": "https://test.example.com",
  "evidence_dir": "evidence/agents/weak-pass-check",
  "autonomy": {"level": "guided", "allowed_supplemental_probes": ["one_discovered_target_readonly_request", "small_visible_control_probe"]},
  "inputs": {"shared_findings_hint": ["<fingerprint>"], "artifacts": ["evidence/recon/site-profile.json"]},
  "deliverables": {
    "evidence_level": "ui_screenshot", "screenshot_required": true, "equivalent_evidence_allowed": true,
    "found": {
      "raw_screenshot": "reports/<系统名称>/<漏洞名称>.assets/原始截图.png",
      "annotated_screenshot": "reports/<系统名称>/<漏洞名称>.assets/证据截图.png",
      "selected_request_response": "evidence/agents/<agent>/selected-request-response.http",
      "markdown_report": "reports/<系统名称>/<漏洞名称>.md",
      "burp_raw_packets_required": true
    },
    "not_found": {
      "status_screenshot": "reports/<系统名称>/not-found/<漏洞名称>.assets/状态截图.png",
      "markdown_report": "reports/<系统名称>/not-found/<漏洞名称>.md"
    }
  },
  "constraints": [
    "page_group_id 仅用于路由归因，共享会话可见性不授予额外权限；只操作本节点需要的页面和数据；context 操作前确认共享状态影响",
    "不建树节点、不派子 Agent；不做破坏性操作或 DoS；candidate 不得写成 validated；不写入源文件区域",
    "新发现回填 attack_path_finding_add；当前 Skill 范围外的新线索写进 hypotheses 交主 Agent 决策",
    "在分配的漏洞 Skill 范围内自主决定测试路径、深度和请求数量；浏览器与抓包用 MCP 浏览器工具",
    "证据与报告口径见 references/vulnerability-subagent.md；纯 API/passive 类用原始 selected request/response（不脱敏），仅体积受限才截断并标记 truncated",
    "过程中用 attack_path_node_update(..., expectedRevision) 记录进度；单步较长时调 xsec_subagent_heartbeat；结束前用 xsec_subagent_complete(status, conclusion) 提交终态，不要用节点更新写终态"
  ]
}
```

## 状态镜像（可选）

`evidence/orchestrator/status.json` 字段：`phase`、`tree_summary`、`observations[{id,signal,evidence}]`、`hypothesis_queue`、`issues[{id,node_id,severity,title,status,report,annotated_screenshots,evidence_level}]`、`not_found[{id,title,reason,report}]`、`wins[{id,title,unlocks}]`。每条 issue 的详情文档含保留完整原始 headers 和敏感值的 Burp Raw 风格请求/响应；UI 可见类含关键证据截图，API/passive/协议类含 selected request/response 或请求指纹并写 `screenshot_unavailable_reason`。

## 实时总结与收敛

阶段变化、子 Agent 启动/完成、finding 变 validated、战果解锁后输出简短进度：当前阶段；测试树节点数、运行中和已确认漏洞数；侦查和已发现的关键项；进行中与等待的节点及原因；issue / not-found / win 清单；下一步。区分已验证问题、普通观察和下一步假设，不把未验证风险写成已确认漏洞。

满足任一条件时停止派发新子 Agent，只做汇总和报告：速率、账号或时间预算达到限制；没有新共享发现能触发 enabled 漏洞 Skill；所有已建节点都已完成且没有待复现 finding；目标进入 challenge/阻断状态，需要用户提供目标或人工处理；用户要求停止、暂停或只输出当前状态。
