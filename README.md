# Web 安全测试编排 Skill（树状 · 主/子 Agent）

`x-sec-agent` 是上级调度 skill。主 Agent 用 MCP 管理一棵**树状测试任务**：按观察信号在树上生成节点、为节点分配页面分组、派发子 Agent，并维护实时进度、问题清单和战果。

浏览器点击、Playwright 交互和抓包已由本系统 MCP 接管（完整共享浏览器，`page_group_id` 仅作路由归因，抓包用浏览器 network 工具）。**不再使用外部 adapter 或 mitmproxy。**

## 核心思想

- 先观察，再触发；不要启动时一股脑跑完所有漏洞 Skill。
- **树状扩展**：发现触发点 → 判断测试价值 → `attack_path_node_create` 建节点 → `xsec_subagent_dispatch` 派子 Agent → 子 Agent 回填 `attack_path_finding_add` → 主 Agent 据新发现继续建节点。树在过程中动态生长。
- **分层建树**：树的层级 = 执行/依赖顺序，**不要把所有节点平铺在 root 下**。采用「阶段骨架 + 依赖/解锁链」：root 下按需建阶段骨架节点（`recon`/`pre-auth`/`auth`/`post-auth`/`surface-specific`/`passive-review`/`chain-analysis`，`kind="phase"`）；每个测试节点的 `parent_id` 是解锁/触发它的上游节点或对应阶段节点；上一层结果解锁的下一层利用挂到上游测试节点下，逐层往下链接。
- **完整共享浏览器 + 页面分组归因**：主/子 Agent 共享同一 `browser_session_id`、全部页面/标签页、登录态、存储和 network 记录；每个子 Agent 的 `page_group_id` 只用于路由与归因，不隔离页面。context 级操作允许所有 Agent 执行，但会影响全局共享状态。
- **范围口径**：`scope_policy` 只做资产归因，不是访问边界；自然发现的 HTTP/HTTPS 目标可继续测试，仍受低影响约束和宿主审批。
- **证据口径**：xSec 不做自动脱敏，共享发现、委派和报告保留观察到的原始值，只选取证明问题所需的最小片段。
- **共享发现知识库**：任何 Agent 的发现（按 fingerprint 去重）对全体可见（`attack_path_findings_list`）。
- **角色门控**：主/子 Agent 用同一 MCP key，用 `X-XSEC-Role` 区分；子 Agent 调用主 Agent 专属工具会被拒绝 `role_denied`。
- 顶层 `skills/` 下所有 Skill 都通过 `## 编排适配` 暴露适用场景、触发信号、测试前置环境、必需工件、解锁输出和阻断条件。
- `config/vulnerability-skills.yaml` 用 `scenario_playbooks` 描述常见路线，用 `activation.requires_environment` 控制是否真的派发子 Agent。
- `autonomy.default_level` 默认 `guided`：注册表是正式派发路径，未覆盖的新线索写入 `hypothesis_queue`，做低影响补证后再转成节点或建议。
- 测试初期先并行侦查：站点画像、API 路径发现、登录入口归集，以及按画像条件执行 DirSearch（批量路径探测经系统终端 MCP 跑 dirsearch 类工具，命中后用浏览器核实）。浏览器/验证流量经 MCP 浏览器 network 抓包，敏感命中自动落盘为共享发现。
- 每个被触发的漏洞 Skill 开一个独立子 Agent（一个节点一个 Skill）；前序节点只通过发现/wins 解锁后续节点，不代表后续已确认漏洞。
- 子 Agent 只围绕被分配的一个节点 + 一个 Skill，但可按 payload 的 `autonomy` 预算对自然发现目标做只读请求或小范围控件探测补齐证据。
- 每个已验证问题和战果都必须引用 evidence path、shared_finding fingerprint 或来源 artifact。
- 已发现和未发现漏洞都落 Markdown 文档并分别存储；UI 类优先截图和红框标注，API/passive/协议类使用保留完整原始 headers 与敏感值的 selected request/response 或请求指纹作为等价证据。

## MCP 工具

- 树：`attack_path_node_create`（主）、`attack_path_node_update`、`attack_path_node_get`、`attack_path_list`。
- 共享发现：`attack_path_finding_add`、`attack_path_findings_list`。
- 子 Agent：`xsec_subagent_dispatch`（主）、`xsec_subagent_register_session`、`xsec_subagent_status`。
- 页面分组：`xsec_subagent_dispatch` 已原子创建（不需要先调 `xsec_page_group_create`）、`xsec_page_group_use` 设置 current page；浏览器工具透传 `page_group_id`/`page_id`。

树与共享发现存活在 MCP，是权威状态源，桌面端「测试树」界面实时可视化每个节点及其运行中子 Agent 的输出。

## 快速流程

1. 确认测试目标 URL，确定 `XSEC_RUN_ROOT`。
2. `attack_path_node_create(title="root", kind="root")` 建根；按需在 root 下建阶段骨架节点（`kind="phase"`），后续节点挂到阶段节点或解锁它的上游节点下，不平铺在 root。用 MCP 浏览器做 scout（network 抓包）生成 forms/actions/routes/API inventory/request corpus，发现写入 `attack_path_finding_add`。
3. 并行侦查子 Agent（各自 `page_group_id`）：站点画像、API 路径发现、登录入口归集；server_script/unknown 站点执行 Web 根路径 DirSearch，SPA 跳过。
4. 对发现的 API base path/接口目录执行 API DirSearch。
5. 提供账号密码时直接登录（共享浏览器全体可用）；否则发现登录框/认证 API/后台入口后建弱口令节点做全量凭据审计。
6. 用 `scenario_playbooks` 识别路线，再用每个 Skill 的 activation/artifacts/environment 决定是否建节点派发。
7. 每个待测节点 `xsec_subagent_dispatch(node_id, browser_session_id)`（服务端同时生成 page group）；子 Agent 用该 ID 归因，但可操作共享会话中的全部页面与网络上下文。
8. 子 Agent 发现 UI 类漏洞后用 MCP 截图 + 红框标注，生成 `reports/<系统名称>/<漏洞名称>.md`；API/passive/协议类保存等价证据。
9. 子 Agent 未发现时生成 `reports/<系统名称>/not-found/<漏洞名称>.md`；`attack_path_node_update` 更新节点。
10. 主 Agent 读 `attack_path_list` + `attack_path_findings_list`，把新发现建成新节点扩展树，`parentId` 指向回填该发现的子 Agent 节点，往下嵌套成利用链。
11. 收尾前跑 `xsec-passive-scanning` 复核敏感命中；调用 `xsec-vulnerability-chain-analysis` 做组合链分析。
12. `xsec_report_submit` 出最终报告。

## 配置

复制或维护 `config/vulnerability-skills.yaml`（可建 `.local.yaml`）。当前把 35 个漏洞测试 Skill 放入 `vulnerability_skills`，把 `xsec-passive-scanning`、`xsec-code-audit-bridge` 和 `xsec-vulnerability-chain-analysis` 放入 `post_processors`，合计覆盖 `skills/` 下全部 38 个 Skill。`adapters.browser` 声明浏览器由 MCP 接管；`mcp_tools` 声明主 Agent 专属与共享工具。未触发或环境不满足的 enabled Skill 保持 idle/blocked；未注册或 disabled 的只记录为建议。

### 自由度配置

`autonomy` 控制 Agent 主动补证范围：`conservative` 只按注册表派发；`guided`（默认）允许低影响补证（自然发现目标的只读请求、小范围控件探测、API 文档可访问性确认）；`aggressive` 允许更宽的低速率多分支补证，仍受低影响和禁止破坏性动作约束。弱口令按 `credential_audit_policy` 执行全量凭据审计，默认单线程、命中即停，保证在有限时间内跑完全量字典。

## 渐进式披露

- 主 Agent 读 `references/main-agent.md` 和 `references/routing-index.md`（信号 → Skill 一行一个，由 `python3 scripts/build_routing_index.py` 从 `config/vulnerability-skills.yaml` 生成；改 yaml 后重新生成，`python3 -m unittest discover -s scripts -p 'test_*.py'` 校验一致）。
- 漏洞测试子 Agent 读 `references/vulnerability-subagent.md`。
- 浏览器操作直接用 MCP 浏览器工具（带 `page_group_id`），无需读额外 adapter 文档。

顶层 `SKILL.md` 只做角色路由和边界声明。

## 评估用例

`evals/evals.json` 保存授权、共享状态、证据披露与停止条件的行为验收案例；这些案例需在隔离环境验证，不向真实目标自动执行。
