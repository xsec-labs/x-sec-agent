# 主 Agent 编排指南（树状 · MCP 管理）

先读 [运行边界与证据口径](security-boundaries.md)，本文所有操作受该边界约束。

主 Agent 负责测试流程，而不是具体漏洞测试细节。主 Agent 用 MCP 持有并管理一棵**树状测试任务**：按观察信号在树上生成节点、为节点分配页面分组、派发子 Agent，并维护实时进度与战果。

## 松绑总则

本指南给出的是**目标和边界**，不是死步骤。主 Agent 应像有经验的安全测试负责人一样主动判断：

- 下面的流程、侦查清单、事件触发表、playbook 都是**参考路径**，不是必须逐条执行的清单。主 Agent 根据目标实际情况自主决定先做什么、后做什么、跳过什么、追加什么。
- 注册表（`vulnerability-skills.yaml`）是派发主路径，不是天花板。观察到注册表之外的有价值线索时，主 Agent 主动记录 hypothesis、做低影响确认、自行决定是否建节点或建议新增 Skill，而不是因为"没注册"就放弃。
- 请求量、并发和时间遵守已批准上限；达到预算、风控或服务异常停止条件即停止相关动作。
- 遵守低影响与预算约束、最少信息披露、禁止破坏性/DoS、证据真实性和源目录只读边界；`scope_policy` 只做资产归因，不是访问边界。

## 子 Agent 派发强度（核心能力）

主 Agent 最重要的能力是**像有经验的技术负责人一样派发子 Agent**。好的派发不是给死步骤，而是给目标、给边界、给上下文，然后信任子 Agent 自主探索：

1. **主动判断什么值得派子代理**：不按注册表清单逐条跑，而是按"这个发现有没有测试价值、现在能不能测、测了能不能产出有用结论"来判断。值得测的才建节点派发；价值低或环境不满足的果断跳过或标 waiting。
2. **给目标和边界，不给死步骤**：payload 里写清楚"测什么漏洞、为什么派你（activation_reason）、目标是什么、可用上下文有哪些、硬边界是什么"；**不要**写"第一步做 X、第二步做 Y、第三步做 Z"。具体怎么测由子 Agent 读 Skill 后自行决定。
3. **给足上下文**：把相关的共享发现 fingerprint、artifact 路径、已验证 issue、登录态、测试账号都放进 payload。子 Agent 拿到的上下文越完整，越能自主做出好判断。
4. **信任子 Agent 的自主探索**：子 Agent 在边界内自行决定测试路径、请求数量、验证深度。主 Agent 不微观干预子 Agent 怎么测，只看结果：节点结论、共享发现回填、证据质量。
5. **子 Agent 发现新方向时主动接住**：子 Agent 回填的新信号、hypothesis、observations，主 Agent 主动读、主动建新节点、主动扩展树。子 Agent 越能自主探索，主 Agent 越要主动接住它的产出，而不是只等"分配的那一个漏洞测完没"。
6. **并行优先**：没有依赖关系的节点尽量并行派发，让多个子 Agent 同时探索不同测试面。有依赖关系的（比如登录后才能测的）等前置完成再派。

## 何时读取

当你是主 Agent，或用户要求编排 Web 安全测试流程时，读取本文件。`references/vulnerability-subagent.md` 是子 Agent 的指南，主 Agent 需要了解子 Agent 的工作方式时可参考，但不需要按它执行。

## 已接管能力（直接用 MCP，不要自建）

- 浏览器由本系统 MCP 接管；直接调用 MCP 浏览器工具拉起并操作浏览器。抓包用浏览器自带 network 工具。**不启动 mitmproxy，不分配 proxy 端口。**
- 主 Agent 与所有子 Agent 共享**同一浏览器会话**（同一 `browser_session_id` = 共享 BrowserContext，共享登录态）。
- 用**页面分组**路由和归因各子 Agent：`xsec_subagent_dispatch` 派发时由服务端为每个子 Agent 生成一个 `page_group_id`（不需要先建分组），但不隔离页面；所有 Agent 按各自节点需要操作页面和 context。context 级操作会影响全局共享状态，执行前确认任务需要、角色权限及共享状态影响。
- `browser_network_requests` 返回完整原始值，xSec 不做自动脱敏；只保留证明问题所需的最小片段，不要把无关凭据复制进报告或最终回复。

## MCP 工具（主 Agent 的树管理入口）

- 树：`attack_path_node_create`（仅主）、`attack_path_node_update`、`attack_path_node_get`、`attack_path_list`、`attack_path_node_delete`（仅主）。调用 `attack_path_node_update`/`attack_path_node_delete` 前，必须把 `attack_path_node_get`/`attack_path_list` 返回的顶层 `revision`（底层就是该节点的 `updated_at`）原样作为 `expectedRevision` 传回；这是按单个节点判断的乐观锁，不是整棵树共用一个版本号。并发更新同一节点时，带旧 `expectedRevision` 的调用会被拒绝，按最新状态重试，不要覆盖别的 Agent 刚写的结论。
- 共享发现知识库（全体可见、`fingerprint` 去重）：`attack_path_finding_add`、`attack_path_findings_list`、`attack_path_finding_delete`（仅主，清理过时发现）。
- 子 Agent 编排：`xsec_subagent_dispatch`（仅主，派发）、`xsec_subagent_cancel`（仅主，收回失控/超预算子 Agent）、`xsec_subagent_status`（仅主，轮询全部子 Agent）、（子 Agent 侧）`xsec_subagent_register_session`（登记）、`xsec_subagent_heartbeat`（存活心跳）、`xsec_subagent_complete`（正式收口，`status` 取 `done`/`vuln`/`failed`/`cancelled`——未发现漏洞也是 `done`+`conclusion` 说明，没有单独的 not-found 取值）。
- 页面分组：`xsec_subagent_dispatch` 已原子创建该子 Agent 的 page group，不需要先调 `xsec_page_group_create`；`xsec_page_group_use` 只用于设置分组的 current page。
- 主 MCP 里还有同名别名 `xsec_tree_*`、`xsec_shared_finding_*`、`xsec_shared_findings_list`（参数 snake_case，如 `parent_id`、`node_id`；上面这组用驼峰）。批量系统提示词写的是 `xsec_` 这组；两组操作同一份数据，以当前 `tools/list` 为准。

树与共享发现是**权威状态源**，存活在 MCP 里，桌面端「测试树」界面实时可视化。本地 `evidence/orchestrator/status.json` 仍可作人类可读镜像，但派发决策以 MCP 树/发现为准。

## 核心循环（树状扩展）

```
发现资产/目录/接口/文件/凭据/报错/版本/权限点
   → 判断测试价值 → attack_path_node_create(parentId=<触发它的上游节点>) 生成节点
   → xsec_subagent_dispatch 派子 Agent（同时生成其 page group）
   → 子 Agent 回填 attack_path_finding_add + 更新节点
   → 主 Agent 读新发现，把它建成【回填该发现的那个节点】的子节点，继续往下扩展树
```

信息收集 → 发现触发点 → 深度测试 → 发现新触发点 → 继续测试。树在过程中动态生长，直到分配范围完成、预算耗尽或停止条件触发。

## 分层建树（parent_id 语义 · 核心）

**树的层级 = 执行/依赖顺序，不是把所有节点平铺在 root 下。** `attack_path_node_create` 接受 `parentId`；每次建节点都必须显式想清楚"这个节点的父节点是谁"。最常见的错误是把所有测试节点的 `parentId` 都设成 root，导致树只有两层（root → 一堆平级 task），看不出执行顺序，也无法表达"往下继续链接下一层利用"。**禁止这样做。**

采用**阶段骨架 + 依赖/解锁链**的组合分层：

### 1. 阶段骨架层（root 的直接子节点）

root 下只挂**阶段骨架节点**，作为分层容器，按需创建（用到哪个阶段才建，不必一次全建）：

| 阶段骨架节点 | kind | 何时创建 |
| --- | --- | --- |
| `recon 侦查` | `phase` | 开始侦查时 |
| `pre-auth 未登录面` | `phase` | 有未登录可测面时 |
| `auth 凭据获取` | `phase` | 需要弱口令/登录获取凭据时 |
| `post-auth 登录后` | `phase` | 获得登录态后 |
| `surface-specific 专项面` | `phase` | 出现文件/AI/SSRF 等专项面时 |
| `passive-review 被动复核` | `phase` | 收尾复核阶段 |
| `chain-analysis 组合链` | `phase` | 收尾组合分析阶段 |

阶段骨架节点的 `parent_id` = root。`kind="phase"`（DB 的 `kind` 是自由文本，UI 对未知 kind 用默认样式渲染，可接受）。

### 2. 依赖/解锁链（阶段内往下嵌套）

阶段内的节点**不要**都平挂在阶段节点下。用 `parent_id` 表达"谁解锁了谁"：

- 一个测试面/发现**首次进入某阶段**时，其节点挂到对应阶段骨架节点下（`parent_id` = 阶段节点）。
- 一个节点如果是"**由另一个测试节点的结果直接解锁的下一层利用**"，就挂到那个**上游测试节点**下（`parent_id` = 上游节点），而不是阶段节点或 root——这就是"往下继续链接下一层利用"。
- 子 Agent 回填新发现后主 Agent 建的新节点，`parent_id` = **回填该发现的那个子 Agent 的节点**，让利用链一层层往下长。

### 3. parent_id 选择规则（每次建节点必须走一遍）

1. 是阶段骨架节点吗？→ `parent_id` = root。
2. 是某阶段里一个**新的、独立的**测试面（无单一上游触发点）吗？→ `parent_id` = 该阶段骨架节点。
3. 是"上一个测试节点的结果直接解锁/触发出来的"吗？→ `parent_id` = 那个上游测试节点，往下嵌套。
4. 跨阶段推进（例：recon 的登录面 → auth 的弱口令 → post-auth 的越权）用**阶段切换**表达：新节点挂到新阶段骨架下；同一条利用链内的逐层深入用**父子嵌套**表达。
5. **绝不**把所有节点平铺在 root 下或单一节点下。

### 4. 期望的树形（示例）

```
root: <目标>
├─ recon 侦查 (phase)
│   ├─ site-profile 站点画像
│   ├─ api-path-discovery API 路径发现
│   └─ login-surface 登录面归集         ──(发现登录框)──┐
├─ pre-auth 未登录面 (phase)                            │
│   ├─ transport-security 传输层安全                    │
│   ├─ version-info-exposure 版本信息泄露               │
│   └─ unauth-access 未授权访问(API 端点)               │
│        └─ internal-network-leakage 内网地址泄露   ← 由未授权访问结果解锁，往下嵌套
├─ auth 凭据获取 (phase)                                │
│   └─ weak-pass-check 弱口令  ←────────────────────────┘ 由 login-surface 解锁
│        └─ (登录成功, authenticated_session_obtained)
├─ post-auth 登录后 (phase)   ← 由弱口令/登录成功解锁
│   ├─ jwt-security JWT 安全
│   ├─ access-control-idor 越权
│   │    └─ sensitive-data-exposure 敏感数据访问   ← 由越权结果解锁，往下嵌套
│   └─ session-token-invalidation 会话失效
└─ chain-analysis 组合链 (phase)
```

对照当前问题：如果所有 weak-pass / transport-security / unauth-access / cookie 等节点都是 root 的直接平级子节点，就是**错误的平铺**，必须改成上面这种按执行顺序分层、逐层往下链接的结构。

## 派发子 Agent 的登记顺序

桌面端「测试树」按 `tree_nodes.subagent_id -> subagent_sessions.session_id` 切换右侧终端。为了让 UI 正确映射，派发时按以下顺序登记（顺序是为了 UI 映射正确，不是限制你怎么测）：

1. 对触发点调用 `attack_path_node_create(parentId=<上游节点/阶段节点>, ...)`，拿到 `nodeId`。**必须按上一节的 parentId 选择规则挑好父节点**——父节点是"解锁/触发它的那个上游节点"或对应阶段骨架节点，不是无脑填 root。
2. 调用 `xsec_subagent_dispatch(node_id, browser_session_id)`，拿到 `subagent_id` 和服务端生成的 `page_group_id`；这一步原子地创建专属 page group、子 Agent 会话并把 `subagent_id` 写回树节点。不要先调 `xsec_page_group_create`，也不要自己生成 page group ID。
3. 启动子 Agent 时 payload 带 `node_id`、`subagent_id`、`page_group_id`、`vulnerability_skill`、`activation_reason`，以及你能给的全部相关上下文（共享发现、artifact、登录态、测试账号等）。
4. 子 Agent 启动后先调用 `xsec_task_profile`，再调用无参数的 `xsec_subagent_register_session` 登记自己；身份和 session 由子 Agent capability 与桌面运行器绑定，主 Agent 不代为登记。
5. 缺 `session_id` 时，树节点能显示但 UI 无法切到该子 Agent 终端——尽快补登记。
6. 子 Agent 运行期间定期调用无参数的 `xsec_subagent_heartbeat`（尤其是单步较长时）；超时不发心跳会被判定失联。
7. 子 Agent 收尾调用 `xsec_subagent_complete(status, conclusion, reason?)` 正式收口——不是在文本里写个结束标记；没有这一步，主 Agent 轮询 `xsec_subagent_status` 拿不到可靠的完成信号。
8. 子 Agent 失控（超预算、超时、跑偏）时，主 Agent 调用 `xsec_subagent_cancel(subagent_id, reason)` 主动收回，不要等它自己退出。

## 主 Agent 职责

主 Agent 的核心职责是**判断、调度、接住产出**，而不是替子 Agent 决定怎么测：

- 确认目标、账号和速率限制。
- 读取 `config/vulnerability-skills.yaml` 了解有哪些已注册 Skill、各自触发条件和解锁关系；把 playbook 当场景提示，把每个 Skill 的 `activation` 当派发参考条件——但不是唯一依据，注册表之外的合理线索同样值得探索。
- `attack_path_node_create(title="root", kind="root")` 建根节点；再按需在 root 下建阶段骨架节点（`kind="phase"`，见「分层建树」一节）。
- 初期做基线 scout（用 MCP 浏览器访问目标 + network 抓包），把 forms、actions、routes、API 线索、登录入口、报错、版本、疑似凭据等写入 `attack_path_finding_add`。
- 对每个有测试价值的发现 `attack_path_node_create` 生成子节点（写 `parentId`、`kind`、`target`、`testValue`、`brief`）。**`parentId` 必须按「分层建树」的选择规则挑**：解锁它的上游节点或对应阶段节点，而不是一律挂 root。**判断测试价值是主 Agent 的核心判断权**——不必拘泥于注册表，发现值得测的就可以建节点。
- 派发前参考 `activation.requires_environment`、`requires_artifacts`、阻断信号；环境不满足时主 Agent 自行判断：是跳过、标记等待、还是先做低影响补证把环境凑齐。不必机械地"不满足就 skipped"。
- 为待测节点调用 `xsec_subagent_dispatch(node_id, browser_session_id)` 派发（服务端同时生成该子 Agent 的 page group；节点自动转 running 并绑定 subagent）。payload 给足上下文，不给死步骤。
- 轮询 `xsec_subagent_status` + `attack_path_list`，读 `attack_path_findings_list` 获取子 Agent 新发现。**主动接住子 Agent 的产出**：新信号、hypothesis、observations 都值得读，都可能扩展树。
- 把子 Agent 的新发现转成新节点继续扩展树；前一个节点的战果只解锁后续节点，不等于后续已确认漏洞。
- 若用户提供测试账号密码，优先直接登录并保存登录态（共享浏览器全体可用），不必把「弱口令测试」作为获得登录态的必要前置。
- 收尾：先跑 `xsec-passive-scanning` 复核共享发现里的敏感命中；再尝试 `xsec-vulnerability-chain-analysis` 判断能否组合成更高风险链路；最后 `xsec_report_submit` 出报告。收尾顺序可按实际情况调整。

主 Agent 一般不直接执行漏洞利用逻辑。但如果某个验证简单、风险低、且能快速确认信号的小测试，主 Agent 可以自己做，不必非派子 Agent——判断权在主 Agent。

## 自主度与假设队列

主 Agent 在已批准的请求、并发和时间上限内组织任务；下列档位不改变这些上限，也不改变 `scope_policy` 只做归因的口径。

- `conservative`：只按已注册 activation 派发；缺 artifact 记 waiting，不额外探测。
- `guided`（默认参考）：允许对候选线索做有限补证，例如一次自然发现目标的只读请求、一次页面控件小范围探测、一次 API 文档可访问性确认。
- `aggressive`：允许更宽的低速率枚举和多分支补证，仍禁止破坏性动作、DoS。

- 请求量、并发和时间遵守已批准上限；达到预算、风控或服务异常停止条件即停止相关动作。

`hypothesis_queue` 保存「合理但尚未能触发注册 Skill」的线索。每条建议含：

```json
{
  "id": "hyp-001",
  "title": "疑似 GraphQL 接口暴露",
  "source": "shared_findings",
  "evidence": ["<shared_finding fingerprint 或 id>"],
  "proposed_signal": "api_interface_candidate",
  "allowed_probe": "one_discovered_target_readonly_request",
  "status": "pending|confirmed|dismissed|needs_new_skill"
}
```

确认规则：能映射到现有 Skill 的，建节点并派发；有价值但无对应 Skill 的，主 Agent 自行判断是记 `next_actions`/`skill_ideas`、还是自己做低影响验证、还是标 `blocked`。需写操作或高频请求的，主 Agent 根据风险自行决定。

## 运行目录与只读源文件

主 Agent 在任何侦查、浏览器、报告或子 Agent 任务前，必须确定 `XSEC_RUN_ROOT`；未指定时用仓库下 `.xsec-runs/default/`。`evidence/...`、`reports/...`、`tmp/...` 都是 run-root 相对路径。

源文件区域只读：`SKILL.md`、`references/`、`templates/`、`skills/`、`config/` 不得作为输出目录。`templates/*.md` 只读渲染到 `reports/`。JWT 的 `rockyou.txt` 字典缓存是例外。

## 初期侦查阶段

初期侦查是建议的前置阶段，帮助主 Agent 快速了解目标全貌。所有 HTTP(S) 观察通过 MCP 浏览器 + network 抓包完成。每个侦查子 Agent 分配独立 `page_group_id` 与 `evidence_dir`。侦查发现统一写入 `attack_path_finding_add`。

以下侦查子 Agent 是**推荐组合**，主 Agent 根据目标实际情况自行决定跑哪些、跳哪些、加哪些：

- `site-profile-classifier`：读取 headers、HTML/JS 短摘录、静态资源路径、响应扩展名、server header、路由模式，输出 `site_profile`。
- `api-path-discovery`：从 JS bundle 短摘录、source map 线索、forms/actions、network 请求语料、route-map 中提取 API base path、接口路径、认证 API 和文档路径。
- `login-surface-discovery`：归集登录框、密码字段、认证 API、后台/管理登录入口、DirSearch 发现的登录页面。
- `dirsearch-webroot`：仅在站点画像允许时执行 Web 根路径 DirSearch。
- `dirsearch-api-paths`：对 API base path 或接口目录做 DirSearch；不因 SPA 画像跳过。

侦查产物写入 `evidence/recon/`（如 `site-profile.json`、`api-paths.json`、`login-surfaces.json`、`dirsearch-*.jsonl`），高价值命中同时 `attack_path_finding_add` 供全体消费。

## 站点画像与 DirSearch

`site-profile-classifier` 给出 `site_profile.kind`，主 Agent 参考 it 决定 DirSearch 策略：

- `spa_template`（Vue/React/Angular/Vite/Webpack/前后端分离）：通常不做 Web 根路径 DirSearch，但主 Agent 如果判断前端可能有隐藏路由或配置文件，可以自行决定跑一轮。
- `server_script`（PHP/ASP/JSP/ThinkPHP/Laravel/Struts/传统模板）：建议执行一次受控 Web 根路径 DirSearch。
- `unknown`：证据不足，建议执行一次受控 Web 根路径 DirSearch。

DirSearch 原则：覆盖本节点分配的 host/scheme/端口/path，页面中自然发现的 HTTP/HTTPS 目标记录来源后可继续；保持低影响、低速率、有限字典，不做 DoS 高并发。发现 `admin`、`manager`、`backend`、`login`、`swagger`、`api-docs`、`backup`、`config`、`.env`、source map 等路径时，`attack_path_finding_add` 记录并由主 Agent 判断建节点。API DirSearch 可从 `/api/`、`/api/v1/`、`/swagger/` 等 base path 或文档路径开始，新发现的 API host 记录来源和资产归因，不因 `in_scope=false` 停止。

## 登录与凭据策略

- 用户提供测试账号密码时优先直接登录；登录态在共享浏览器里全体可用，写入 `authenticated_session_obtained`、`post_login_surface_available`，再派登录后节点。
- 未提供但发现登录框/密码字段/认证 API/后台登录框时，按注册表建 `weak-pass-check` 节点。
- 弱口令成功时记 issue/win，用共享登录态重新计算登录后测试队列。
- 登录入口有验证码/OTP/账号锁定/字典限制时，弱口令子 Agent 遵守边界；无法完成返回 `blocked`/`not_found`，不升级为未授权绕过或高频尝试。
- 弱口令按全量凭据审计执行：payload 给出 `max_threads`、`delay_seconds`、`lockout_stop_condition` 和允许凭据来源；默认对选定字典做全量尝试，命中即停。

## 场景 Playbook 与解锁

`scenario_playbooks` 是主 Agent 的预设路线图，用于理解「常见场景下哪些 Skill 可能被后续解锁」，不是执行清单。正式派发以每个 Skill 的 `activation`（信号、工件、环境）为准。无法匹配的新线索进 `hypothesis_queue`。

- 公开面场景：只有目标 URL、未登录时，先跑站点画像、API 发现、登录面归集、必要 DirSearch、传输层/版本/目录/API/中间件/未授权/客户端硬编码和 passive 复核节点。
- 登录面场景：发现登录框/密码字段/认证 API/后台登录入口后，才考虑弱口令、暴力破解防护、验证码/OTP、后期用户名枚举。
- 登录后场景：提供凭据或弱口令成功后，写 `authenticated_session_obtained`，解锁浏览器存储、JWT、会话失效、权限边界、密码策略、密码明文返回、CSRF、CORS、SQL 注入、上传、下载、XSS。
- API 文档/接口场景：发现 API base path、Swagger/OpenAPI/Knife4j/WSDL 或前端提取的疑似后端 path 后，先做 API DirSearch/文档复核或未登录 path 拼接验证，再按结果解锁未授权、CORS、SQL 注入、登录后权限边界。
- 文件面场景：发现上传/下载/预览/导入导出/路径参数后，解锁上传安全、下载访问控制、路径遍历、XSS；上传初始化返回对象存储凭据时再解锁云密钥复核。
- AI 对话场景：发现聊天/RAG/流式模型/模型输出被前端渲染时解锁 LLM prompt security；模型输出进入 HTML/富文本渲染再追加 XSS。
- 敏感信息与 Shiro 场景：network 抓包或客户端分析命中 AK/SK、私钥、SQL 报错、详细错误、内网地址、Shiro rememberMe/deleteMe 后，按 `target_skill` 或信号解锁对应专项；这些命中是候选，不是最终漏洞。

每次子 Agent 完成后，主 Agent 读其回填的共享发现与节点结论，把新增信号建成新节点，重新计算队列。只满足 playbook 但缺环境（无登录态、无测试手机号、无 AI 对话框、无上传控件）时，节点保持 idle/blocked。

## Passive 与敏感信息复核

network 抓包命中只负责标记，不直接生成漏洞结论。主 Agent 在两个时机消费：

- 测试过程中：把高价值命中（`passive_secret_match`、`passive_sql_error_match`、`passive_detailed_error_match`、`passive_internal_ip_match`）转成新节点，触发对应 passive Skill。
- 收尾前：派 `passive-sensitive-review` 子 Agent 读 `skills/xsec-passive-scanning`，遍历 `attack_path_findings_list` 里的敏感命中，按 `target_skill` 分组去重，分配给对应 Skill 做最小化判断和报告。

复核只读取任务需要的证据（保留原始值，只选最小片段）；共享发现使用请求标识、必要摘要与受控证据引用。

## 收尾组合漏洞分析

最终报告前必须尝试 `xsec-vulnerability-chain-analysis`。输入只含已验证 issue、强候选、wins、登录态、敏感命中、API/DirSearch 发现、权限边界观察。目标是判断可闭合链路，例如：

- 信息泄露/默认凭据 → 弱口令/有效登录态 → 后台入口或敏感业务 API。
- API/目录暴露 → 未授权访问 → 内网/错误/配置泄露。
- 弱认证 → 水平/垂直越权 → 敏感数据访问或下载。
- 会话未失效、浏览器敏感存储、JWT 缺陷与越权叠加。

组合分析保持最小化验证；链路无法闭合时生成 not-found/blocked 结论，说明缺哪一跳。

## 配置入口

读取 `config/vulnerability-skills.yaml`。其中 `orchestration_model` 定义节点/发现 payload 契约；`autonomy` 定义低影响补证边界；`scenario_playbooks` 定义解锁路线；`recon` 定义固定侦查；`vulnerability_skills` 定义由信号触发的漏洞测试；`post_processors` 定义收尾复核。`priority` 只在多个 Skill 都满足 activation 时排序。`status: not_installed` 或 `enabled: false` 的条目只能进入建议/等待状态，不派子 Agent。

## 工作流

以下是**建议路径**，主 Agent 根据目标实际情况自主调整顺序、跳过不适用步骤、追加需要的步骤：

1. 确认测试目标 URL。
2. 确定并导出 `XSEC_RUN_ROOT`，确认不在 `skills/`、`templates/`、`references/`、`config/` 下。
3. 读取 `config/vulnerability-skills.yaml` 了解注册表全貌（`scheduler`、`orchestration_model`、`autonomy`、`scenario_playbooks`、`recon`、`vulnerability_skills`、`post_processors`）。
4. `attack_path_node_create(title="root", kind="root")` 建根；后续按「分层建树」在 root 下按需建阶段骨架节点（`kind="phase"`），其余节点挂到阶段节点或解锁它的上游节点下，不要平铺在 root。
5. 用 MCP 浏览器做基线 scout（network 抓包获取 routes、forms、actions、API delta、session 信号、前端资产、匿名响应样本、passive 命中），把发现写入 `attack_path_finding_add`。
6. 按目标情况派侦查子 Agent：`site-profile-classifier`、`api-path-discovery`、`login-surface-discovery`，参考站点画像决定是否跑 `dirsearch-webroot`；对 API 路径做 `dirsearch-api-paths`。每个子 Agent 使用独立的路由归因 `page_group_id`，但共享全部页面和网络上下文。
7. 若用户提供账号密码，直接用共享浏览器登录并写 `authenticated_session_obtained`；否则发现登录框/认证 API 时按 activation 建弱口令节点。
8. 把 scout、DirSearch、API discovery、登录结果、passive 命中转成共享发现。若在 HTML/JS/前端配置/请求语料中提取到疑似后端 path 或任意 API host，写 `frontend_endpoint_path_candidate_detected` 并保存原始候选；跨域或跨 host 不影响继续验证。
9. 用共享发现匹配漏洞 Skill 的 `activation.any_signals`，检查 `requires_artifacts`、`requires_environment`、阻断信号；无法匹配的合理线索进 hypothesis queue 或主 Agent 自行做低影响验证。
10. 对满足条件的节点：`attack_path_node_create(parentId=<上游节点/阶段节点>)` → `xsec_subagent_dispatch(node_id, browser_session_id)` → 启动子 Agent；子 Agent 随后先调用 `xsec_task_profile`，再调用无参数的 `xsec_subagent_register_session`。不满足条件时主 Agent 自行判断是 skipped、waiting 还是先补证。
11. 子 Agent 返回后读 `attack_path_list` + `attack_path_findings_list`，主动把新信号建成新节点，**`parentId` 指向回填该发现的那个子 Agent 节点**（往下嵌套成利用链），重新计算队列。
12. 每次状态变化输出简短实时总结。
13. UI 可见类 validated finding：用 MCP 浏览器截图工具保存原始截图 + `scripts/annotate_screenshot.py` 红框标注；纯 API/passive/协议类保存含完整原始 headers 和敏感值的 selected request/response（network 工具）或请求指纹，并写明无法截图原因；仅在体积受限时截断 body。
14. 队列收敛前跑 passive 复核子 Agent，把敏感命中分配给对应 passive Skill。
15. 调用 `xsec-vulnerability-chain-analysis` 做组合链分析。
16. 队列为空或达到收敛条件后 `xsec_report_submit` 出最终报告和 evidence pack。

## 事件触发模型

漏洞 Skill 由观察信号激活，而不是默认全量运行。每次 scout、子 Agent 返回后，主 Agent 读共享发现重新计算触发队列，把值得测的信号建成新树节点再派发。下表是**参考映射**——主 Agent 可以根据实际情况增减、调整、合并触发动作，不必逐行机械执行：

| 观察信号 | 触发动作 |
| --- | --- |
| `site_profile.kind=server_script` 或 `unknown` | 启动一次受控 Web 根路径 DirSearch（MCP 浏览器 + network 抓包） |
| `site_profile.kind=spa_template` | 跳过 Web 根路径 DirSearch；继续 API 路径发现和 API DirSearch |
| 发现 API base path、接口目录、Swagger/OpenAPI/Knife4j/WSDL | 对 API 路径做受控 DirSearch；解锁 `api-interface-exposure`、`unauth-access`、`cors-misconfiguration`、`sql-injection`，有登录态时看 `access-control-idor` |
| 从 HTML/JS/前端配置/请求语料提取到疑似后端 path 或任意 API host | 记 `frontend_endpoint_path_candidate_detected`，启动 `unauth-access` 做未登录 path 拼接、低影响参数补全、匿名读取验证；前后端跨域不构成阻断 |
| 发现登录框、密码字段、认证 API | 按环境门槛解锁 `weak-pass-check`、`brute-force-protection`、`captcha-otp-defect`；用户名枚举默认放后期 |
| DirSearch 发现后台/管理端/console/admin login | 记 `admin_login_form_detected`，解锁登录面测试和 `middleware-unauth-management`/`unauth-access` 最小化复核 |
| 用户提供账号密码且登录成功 | 保存共享登录态，记 `authenticated_session_obtained`、`post_login_surface_available`，重新计算登录后节点 |
| 弱口令验证成功、获得 session | 记 `issues`/`wins`；写 `authenticated_session_obtained`；重新计算登录后节点 |
| 发现多角色账号、用户切换入口、ID 型资源路径、403/401 边界 | 环境满足时启动 `access-control-idor`、`file-download-access-control` 或登录后 `unauth-access` 对照验证 |
| 登录后发现 Cookie、JWT、Bearer Token、rememberMe、浏览器存储 | 解锁 `browser-sensitive-storage`、`jwt-security`、`session-token-invalidation`、`cookie-security-flags`、`insecure-crypto` |
| network 抓包在 Cookie 头发现 `rememberMe` 或 `deleteMe` | 记 `passive_shiro_cookie_detected`；只有该信号存在才解锁 `shiro-attack-detection`，先验证弱 Key，命中做低影响利用链检测 |
| 发现注册、改密、重置、首次登录改密、管理员创建用户 | 解锁 `password-policy`、`password-storage-return`、`session-token-invalidation`；涉及验证码/OTP 时解锁 `captcha-otp-defect` |
| API 返回客户/订单/用户/手机号/邮箱/证件号等敏感字段 | 记 `sensitive_data_exposure_candidate`；有对象 ID/角色边界解锁 `access-control-idor`，有 CORS 头解锁 `cors-misconfiguration` |
| 发现上传控件、上传 API、对象存储直传凭据 | 解锁 `file-upload-security`；上传后 URL/文件名回显再解锁 `file-download-access-control`、`xss`、`path-traversal` 或 `cloud-secret-leakage` |
| 发现下载、预览、导出、附件 ID、签名 URL、路径参数 | 解锁 `file-download-access-control`、`path-traversal`；登录后对象资源同时解锁 `access-control-idor` |
| 发现搜索/筛选/分页/排序/报表/详情等带参数请求 | 解锁 `sql-injection`；若先命中 SQL 报错，先由 `sql-error-info-leak` 复核再解锁 SQL 注入 |
| 发现 URL 代取、Webhook、回调、远程图片/文件导入、预览外链 | 解锁 `ssrf`；只有具备回连监听或测试目标时才派发 |
| 发现 AI 对话、RAG、流式模型接口、模型输出进入前端渲染 | 解锁 `llm-prompt-security`；模型输出被 HTML/富文本解释再解锁 `xss` |
| 发现 CORS 头、Origin 反射、ACAC=true、跨站可读迹象 | 解锁 `cors-misconfiguration`；需受控测试 Origin 和敏感响应对照 |
| 发现状态变更表单/API 且依赖 Cookie 会话 | 解锁 `csrf-protection-missing`；必须有可逆低影响动作和受控跨站页面 |
| 发现 HTTP 明文、弱 TLS、混合内容、Secure Cookie 缺失 | 解锁 `transport-security`，为 Cookie/会话/密码传输类 finding 提供影响上下文 |
| 发现版本头、默认页、框架/组件版本 | 解锁 `version-info-exposure`；版本指向管理端/配置端再解锁对应专项 |
| 发现 source map、JS 配置、硬编码密钥、客户端包、前端路由清单 | 解锁 `client-hardcoded-secret`；输出的 AK/SK、内部地址、API path 继续解锁云密钥、内网泄露、API 暴露 |
| DirSearch 或 network 命中 `.env`、备份包、Git/SVN、数据库备份、配置文件 | 解锁 `config-backup-leakage`；其中凭据/内网/API/源码线索继续解锁下游 |
| 发现目录索引、敏感目录、对象存储清单、静态目录暴露 | 解锁 `directory-sensitive-leakage`；目录里出现配置/备份/源码再解锁对应专项 |
| 发现堆栈、绝对路径、详细错误、默认错误页 | 解锁 `error-path-leakage`；含 SQL/ORM 关键字再解锁 `sql-error-info-leak` 或 `sql-injection` |
| network 命中秘钥、SQL 报错、详细错误、路径、内网 IP 或 Shiro Cookie | 收尾前先由 `passive-scanning` 分组；再启动 `cloud-secret-leakage`、`sql-error-info-leak`、`error-path-leakage`、`internal-network-leakage`、`shiro-attack-detection` 等专项 |
| 出现两个以上已验证 issue、一个 issue 加关键 win、或 passive 命中可作为前置条件 | 收尾时启动漏洞组合 Skill，判断能否闭合风险链路 |

触发前参考四件事：漏洞 Skill 已注册且 enabled、当前信号满足 activation、必需 artifacts 存在、`requires_environment` 描述的环境真实存在。任一不满足时主 Agent 自行判断：是先做低影响补证把条件凑齐、还是标 idle/waiting/skipped、还是自己直接做简单验证。不必机械地"不满足就 skipped"。

## 状态镜像（本地可选）

MCP 树 + 共享发现是权威状态；如需人类可读镜像，可写 `evidence/orchestrator/status.json`，字段与节点/发现对应：

```json
{
  "ok": true,
  "phase": "post_login",
  "tree_summary": {"nodes": 12, "running": 2, "vuln": 3},
  "observations": [
    {"id": "obs-001", "signal": "login_form_detected", "evidence": "<shared_finding fingerprint>"},
    {"id": "obs-002", "signal": "passive_sql_error_match", "evidence": "<shared_finding fingerprint>"}
  ],
  "hypothesis_queue": [
    {"id": "hyp-001", "title": "疑似 GraphQL 接口暴露", "proposed_signal": "api_interface_candidate", "status": "pending"}
  ],
  "issues": [
    {"id": "issue-001", "node_id": "<node>", "severity": "high", "title": "弱口令登录成功", "status": "validated",
     "report": "reports/测试系统/弱口令登录成功.md",
     "annotated_screenshots": ["reports/测试系统/弱口令登录成功.assets/证据截图.png"],
     "evidence_level": "ui_screenshot"}
  ],
  "not_found": [
    {"id": "not-found-001", "title": "默认密码未命中", "reason": "测试字典内未发现可用默认凭据", "report": "reports/测试系统/not-found/默认密码未命中.md"}
  ],
  "wins": [
    {"id": "win-001", "title": "获得测试账号有效 session", "unlocks": ["browser-sensitive-storage", "jwt-security", "session-token-invalidation", "access-control-idor"]}
  ]
}
```

`issues` 只记已验证或有明确证据的问题；每条 issue 详情文档必须含保留完整原始 headers 和敏感值的 Burp Raw 风格请求/响应；UI 可见类必须含关键证据截图，API/passive/协议类必须含 selected request/response 或请求指纹并写 `screenshot_unavailable_reason`。仅可因体积限制截断 body 并注明。`not_found` 记已验证但未发现的原因并尽量引用状态截图。`wins` 记进展。每条都引用 evidence/screenshot/report 路径或 shared_finding fingerprint。

## 子 Agent 任务 payload

每个子 Agent 只执行**一个节点 + 一个漏洞 Skill**。主 Agent 发送的 payload：

```json
{
  "role": "sub",
  "node_id": "<tree node id>",
  "subagent_id": "<xsec_subagent_dispatch 返回的 id>",
  "page_group_id": "<xsec_subagent_dispatch 返回的 page_group_id>",
  "browser_session_id": "<共享浏览器会话>",
  "agent": "weak-pass-check",
  "system_name": "测试系统",
  "orchestrator_subagent_reference": "references/vulnerability-subagent.md",
  "vulnerability_skill": {
    "id": "weak-pass-check",
    "path": "skills/weak-pass-check",
    "source_repo": "https://github.com/xsec-labs/x-sec-agent.git"
  },
  "autonomy": {
    "level": "guided",
    "allowed_supplemental_probes": ["one_discovered_target_readonly_request", "small_visible_control_probe"]
  },
  "deliverables": {
    "evidence_level": "ui_screenshot",
    "screenshot_required": true,
    "equivalent_evidence_allowed": true,
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
  "activation_reason": "login_form_detected",
  "target": "https://test.example.com",
  "evidence_dir": "evidence/agents/weak-pass-check",
  "inputs": {
    "shared_findings_hint": ["<fingerprint 1>", "<fingerprint 2>"],
    "artifacts": ["evidence/recon/site-profile.json", "evidence/recon/api-paths.json"]
  },
  "constraints": [
    "page_group_id 仅用于路由归因；共享会话可见性不授予额外权限；仅操作本节点需要的页面和数据",
    "不要建树节点、不要派子 Agent；context 操作前确认共享状态影响",
    "不要做破坏性操作或 DoS（硬边界）",
    "candidate 不得写成 validated，必须有复现证据（硬边界）",
    "不要写入源文件区域 SKILL.md/references/templates/skills/config（硬边界）",
    "新发现回填 attack_path_finding_add；测试方向作为发现返回主 Agent",
    "浏览器操作和抓包用 MCP 浏览器工具（network），不启动独立代理",
    "在分配的漏洞 Skill 范围内自主决定测试路径、深度和请求数量",
    "发现当前 Skill 范围外的新线索时，回填共享发现并在 hypotheses 里提出，交主 Agent 决策",
    "UI 可见类 finding 用 MCP 截图工具保存原始截图并红框标注",
    "纯 API/passive/协议类 finding 使用原始 selected request/response 摘录（不脱敏）与受控原始证据引用 或请求指纹作为等价证据；仅可因体积限制截断 body，并标记 truncated",
    "真实发现漏洞生成 reports/<系统名称>/<漏洞名称>.md；未发现生成 not-found 报告",
    "漏洞详情文档用 Burp Raw 风格展示关键请求响应",
    "结束前用 attack_path_node_update(..., expectedRevision) 更新本节点，再调用 xsec_subagent_complete(status, conclusion) 正式收口（不是输出文本结束标记）；单步较长时记得 xsec_subagent_heartbeat"
  ]
}
```

运行中的子 Agent 达到 `scheduler.max_concurrent_subagents` 时，把新节点放入 waiting；有任务完成/失败/取消后补位。队列按 `priority`、触发时间和风险解锁价值排序。

## 实时总结

每次阶段变化、子 Agent 启动/完成、finding 变 validated、战果解锁后，输出简短进度：

```text
当前阶段：post_login
测试树：12 节点，2 运行中，3 已确认漏洞
侦查：站点画像 server_script，Web 根 DirSearch 完成，API 路径 DirSearch 完成
已发现：登录框 1，后台入口 1，认证 API 2，客户信息 API 1
被动命中：SQL 报错 1，内网 IP 2，已建节点分配 passive Skill
进行中：weak-pass-check 完成；access-control-idor 等待第二账号或 ID 型资源证据
问题清单：issue-001 弱口令登录成功 high
未发现：not-found-001 默认密码未命中，原因已写入 not-found 文档
战果：win-001 已获得有效 session，可用于后续浏览器存储、JWT、会话失效、权限边界测试
报告：found 1，not-found 1
下一步：用共享登录态执行已注册的登录后节点；收尾前调用漏洞组合 Skill
```

总结要区分已验证问题、普通观察和下一步假设。不要把未验证风险写成已确认漏洞。

## 收敛条件

满足任一条件时停止派发新子 Agent，只做汇总和报告：

- 速率、账号或时间预算达到限制。
- 没有新共享发现能触发 enabled 漏洞 Skill。
- 所有已建节点都已完成且没有待复现 finding。
- 目标进入 challenge/阻断状态，需要用户提供测试目标或人工处理。
- 用户要求停止、暂停或只输出当前状态。
