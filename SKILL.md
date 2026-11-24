---
name: x-sec-agent
description: 按树状任务组织 Web 安全审查，由主/子 Agent 分工，维护资产归因、原始证据与结论。
---

# Web 安全测试编排（树状 · 主/子 Agent）

这个 skill 是 Web 安全测试的入口和角色路由层。它决定当前 Agent 应该读取哪份说明，而不是把主代理、子代理和漏洞测试细节一次性加载进上下文。

## 执行边界

先读 [运行边界与证据口径](references/security-boundaries.md)。`scope_policy` 只做资产归因，不是访问边界；
共享浏览器不提供隔离或额外权限。xSec 不做自动脱敏：任务 payload、共享发现与报告保留
观察到的原始值，只选取证明问题所需的最小片段。

## 已接管的能力（不要自己实现）

- **浏览器**：由本系统 MCP 接管（Playwright 已封装）。直接调用 MCP 浏览器工具拉起并操作浏览器，不要引入外部浏览器自动化或独立 mitmproxy 代理。
- **抓包**：使用浏览器自带的 network 工具（MCP 浏览器工具透出），不落独立 HAR/proxy。
- **共享浏览器**：主 Agent 与所有子 Agent 共享**同一个完整浏览器会话**（同一 `browser_session_id` = 共享 BrowserContext，共享全部页面、Cookie / localStorage / 登录态与 network 记录）。
- **页面分组归因**：每个子 Agent 仍分配一个 `page_group_id` 供路由、树节点和终端归因，但它不限制页面可见性或操作权限；`page_id` 按节点需要使用。context 级操作影响所有 Agent；执行前确认并发影响。
- **完整网络证据**：`browser_network_requests` 默认返回完整原始 headers；原始数据按受控证据边界处理，展示和委派使用必要的原始摘录（不脱敏）。

## 核心拆分

- **主 Agent（role=parent）**：管理树状测试任务。做初期侦查、把发现写入共享知识库、判断测试价值、在树上创建节点、为节点分配路由用页面分组并派发子 Agent、汇总报告。只有主 Agent 能建节点、派子 Agent 和提交最终报告。
- **漏洞测试子 Agent（role=sub）**：只围绕主 Agent 分配的**一个树节点 + 一个漏洞 Skill** 执行验证。`page_group_id` 用于结果归因，只操作本节点需要的页面与上下文，把新发现回填共享知识库，更新自己节点的状态/结论。**不建节点、不派子 Agent**，新测试方向作为发现返回主 Agent 决策。
- **漏洞 Skill**：只负责某一类漏洞的测试逻辑（`skills/` 下 37 个）。

## 树状扩展模型（核心）

```
发现资产/目录/接口/文件/凭据/报错/版本/权限点
   → 判断测试价值 → 在【触发它的上游节点】下生成任务节点 → 派子 Agent 测试 → 产出新发现 → 在【回填该发现的节点】下继续往下扩展树
```

任务树在预算和低影响约束内更新；新发现的目标按资产归因标记，不因 `in_scope=false` 停止。

**分层建树（关键）**：树的层级 = 执行/依赖顺序，**不要把所有节点平铺在 root 下**。采用「阶段骨架 + 依赖/解锁链」：root 下按需建阶段骨架节点（`recon` / `pre-auth` / `auth` / `post-auth` / `surface-specific` / `passive-review` / `chain-analysis`，`kind="phase"`）；每个测试节点的 `parent_id` 是"解锁/触发它的那个上游节点"或对应阶段节点，**不是一律填 root**。由上一层测试结果直接解锁的下一层利用，挂到上游测试节点下，形成"往下继续链接下一层利用"。详见 `references/main-agent.md` 的「分层建树」一节。

主 Agent 用 MCP 工具持有并管理整棵树：

- 树/节点：`attack_path_node_create`（主）、`attack_path_node_update`、`attack_path_node_get`、`attack_path_list`、`attack_path_node_delete`（主，清理无效节点）。
- **并发更新用 `expectedRevision`**：`attack_path_node_get`/`attack_path_list` 返回的每个节点带顶层 `revision`（底层就是该节点的 `updated_at`）；调用 `attack_path_node_update`/`attack_path_node_delete` 前必须用读到的最新 `revision` 原样作为 `expectedRevision` 传回。这是**按单个节点**判断的乐观锁，不是整棵树共用一个版本号。两个 Agent（或同一 Agent 的两次调用）并发更新同一节点时，带着旧 `expectedRevision` 的调用会被拒绝；按返回的最新状态重试，不要覆盖对方刚写的结论。
- 共享发现知识库（全体可见、按 fingerprint 去重）：`attack_path_finding_add`、`attack_path_findings_list`、`attack_path_finding_delete`（仅主 Agent，清理过时发现）。
- 子 Agent 编排：`xsec_subagent_dispatch`（主，派发）、`xsec_subagent_register_session`（子，登记）、`xsec_subagent_heartbeat`（子，存活心跳）、`xsec_subagent_complete`（子，正式收口；`status` 取 `done`/`vuln`/`failed`/`cancelled`，未发现漏洞也是 `done`+`conclusion` 说明，没有单独的 not-found 取值）、`xsec_subagent_cancel`（主，收回失控/超预算子 Agent）、`xsec_subagent_status`（主，轮询全部子 Agent 状态）。六个工具的完整时序见下面"子 Agent 派发登记协议"。
- 页面分组：`xsec_subagent_dispatch` 已原子创建子 Agent 的 page group，不需要先调 `xsec_page_group_create`；`xsec_page_group_use` 只用于设置分组的 current page；浏览器工具透传 `page_group_id` / `page_id`。
- 主 MCP 里还有同名别名 `xsec_tree_*`、`xsec_shared_finding_*`、`xsec_shared_findings_list`（参数 snake_case，如 `parent_id`），操作同一份数据；以当前 `tools/list` 为准。这组的乐观锁参数是 `expected_revision`（同样取该节点的 `updated_at`，不是独立字段）。

## 子 Agent 派发登记协议

终端左侧测试树按 **tree node → subagent → session_id** 映射终端输出。为了让 UI 正确映射，派发时按以下顺序登记（顺序是为了 UI 映射正确，不是限制你怎么测）：

1. 先建树节点：对每个有测试价值的触发点调用 `attack_path_node_create(parentId, title, kind, target, testValue, brief)`，拿到 `nodeId`。**`parentId` 必须按分层规则挑**——是解锁/触发它的上游节点或对应阶段骨架节点，不是无脑填 root（否则树会平铺成两层，看不出执行顺序）。根任务只对应主 Agent 终端；其它节点才派子 Agent。
2. 派发子 Agent：调用 `xsec_subagent_dispatch(node_id, browser_session_id)`，拿到 `subagent_id` 和服务端生成的、仅用于路由和归因的 `page_group_id`；这个调用原子地创建专属 page group、子 Agent 会话并把 `subagent_id` 绑定回树节点。不要先调 `xsec_page_group_create`。
3. 启动子 Agent 时，任务 payload 必须包含：`node_id`、`subagent_id`、`page_group_id`、`vulnerability_skill`、`activation_reason`、目标、动作与预算边界、必要证据摘要和受控证据引用。
4. 子 Agent 启动后先调用 `xsec_task_profile` 获取 capability 绑定上下文，再立即调用无参数的 `xsec_subagent_register_session` 登记自己。身份、运行 session 与页面分组由子 Agent capability 和桌面运行器绑定，主 Agent 不代为登记。
5. 子 Agent 在验证过程中定期调用无参数的 `xsec_subagent_heartbeat`（尤其是单次动作较长时，例如等待页面、重放请求）；超过预期时长不发心跳会被判定失联。更新节点状态用 `attack_path_node_update(nodeId, status, testValue, conclusion, expectedRevision)`（见上文"并发更新用 `expectedRevision`"）。
6. 子 Agent 收尾必须调用 `xsec_subagent_complete(status, conclusion, reason?)` 正式收口，不能只在文本里写"测试完成"当结束标记——没有这一步，主 Agent 和终端 UI 都拿不到可靠的结束信号。主 Agent 轮询 `xsec_subagent_status` 和 `attack_path_list` 汇总所有子 Agent 的进度和结论。
7. 子 Agent 失控（超预算、超时、偏离被分配的 Skill/节点）时，主 Agent 调用 `xsec_subagent_cancel(subagent_id, reason)` 主动收回；不要指望子 Agent 自己会退出。

UI 切换规则：点击根节点显示主 Agent 的 session 输出；点击其它节点显示其 `subagent_id` 对应的 `session_id` 输出。缺少 `xsec_subagent_register_session` 时，树节点会存在，但右侧终端无法切到该子 Agent。

`config/vulnerability-skills.yaml` 维护 `scenario_playbooks`、`recon`、`vulnerability_skills` 和 `post_processors`，作为**主 Agent 判断某发现是否值得建节点、该激活哪个漏洞 Skill**的注册表。playbook 只是路线提示，真正派发看每个 Skill 的 `activation`（信号、工件、环境）——但主 Agent 不必拘泥于注册表，新线索先记录，授权与前置条件满足后才可进入分配范围。

`xsec-passive-scanning` 和 `xsec-vulnerability-chain-analysis` 是收尾处理节点，不在启动阶段默认运行。

`autonomy.default_level` 默认 `guided`：注册表是派发主路径；观察到合理但未注册的新线索时，主 Agent 可记录 hypothesis，做一次低影响确认或补充侦查，再决定是否转成新节点或建议新增 Skill。主 Agent 遵守已批准的请求、并发和时间上限，达到预算或停止条件即结束对应动作。

## 运行产物与源文件边界

- `SKILL.md`、`references/`、`templates/`、`skills/`、`config/` 是源文件区域，运行时只读，禁止写入或把报告/证据/临时文件保存到这些目录。
- `templates/*.md` 只作只读模板；报告渲染到 `reports/<系统名称>/...`，不修改模板本身。
- 主 Agent 启动前确定 `XSEC_RUN_ROOT`；未提供时默认仓库下 `.xsec-runs/default/`；所有 `evidence/`、`reports/`、`tmp/` 等相对它。
- `skills/xsec-jwt-security/wordlists/rockyou.txt` 是有意保留的长期字典缓存，不按运行产物处理。

## 证据分级要求

- UI 可见类 finding：用 MCP 浏览器截图工具保存原始截图，并用 `scripts/annotate_screenshot.py` 红框标注；`screenshot_required: true`。
- API / passive / 纯协议 / 无可视化类 finding：截图是优先证据但非硬门禁；可用 selected request/response（来自浏览器 network 工具）、请求指纹或完整原始响应作为主证据，并写明 `screenshot_unavailable_reason`。仅在体积受限时截断 body 并注明。
- 主 Agent 验收 `validated` 报告必须看到可复现证据链：关键截图或等价证据、标明敏感字段处理方式的请求响应摘录及受控原始证据引用、触发条件和影响说明。
- 未发现/阻断结果优先保存状态截图；无可视化界面时引用能说明覆盖范围或阻断原因的最小证据。

## 渐进式披露

先判断当前角色，只读取对应文件：

| 当前角色/任务 | 读取 |
| --- | --- |
| 主 Agent：确认目标、基线 scout、管理测试树、按信号建节点、分配页面分组、派发子 Agent、汇总报告 | `references/main-agent.md` |
| 漏洞测试子 Agent：已收到 `node_id`、`vulnerability_skill`、`page_group_id`、`activation_reason` 等任务 payload，需要测试并生成发现/未发现文档 | `references/vulnerability-subagent.md` |
| 新增或调整漏洞 Skill 激活条件、场景 playbook、解锁输出 | `config/vulnerability-skills.yaml`；同步更新对应 Skill 的 `## 编排适配` |

不要同时读取主代理和子代理详细说明，除非当前任务确实跨越两个角色。
