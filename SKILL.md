---
name: x-sec-agent
description: Web 安全测试上级编排 skill。按观察信号调度侦查、浏览器流量 adapter、漏洞子代理、被动复核、组合分析和报告输出。
---

# Web 安全测试编排

这个 skill 是 Web 安全测试的入口和角色路由层。它决定当前 Agent 应该读取哪份说明，而不是把主代理、子代理、浏览器采集和漏洞测试细节一次性加载进上下文。

核心拆分：

- 主代理：负责测试流程编排、初期侦查扇出、漏洞 Skill 激活、子代理分配、进度/问题/战果账本。
- 侦查子代理：负责站点性质判断、API 路径发现、DirSearch、登录入口归集和 passive hook 结果索引。
- 漏洞测试子代理：围绕主代理分配的一个漏洞 Skill 执行验证；可做受限补证，但新测试方向必须返回主代理决策。
- browser traffic adapter：只负责浏览器操作、抓包、passive hook、flow 归一化和证据复现。
- 漏洞 Skill：只负责某一类漏洞的测试逻辑。

默认 browser traffic adapter 是 `web-pentest-browser-flow`。

编排模型：

- `config/vulnerability-skills.yaml` 维护 `scenario_playbooks`、`recon`、`vulnerability_skills` 和 `post_processors`。
- 顶层 `skills/` 下每个 Skill 都应有 `## 编排适配`，说明适用场景、触发信号、测试前置环境、必需工件、解锁输出和阻断条件。
- 主代理只把满足 activation、artifact、environment 的 Skill 派发给子代理；子代理只执行一个 Skill，并把新观察信号返回给主代理重新计算队列。
- `xsec-passive-scanning` 和 `xsec-vulnerability-chain-analysis` 属于收尾处理节点，不在启动阶段默认运行。
- `autonomy.default_level` 默认是 `guided`：注册表仍是派发主路径；当观察到合理但未注册的新线索时，主代理可以记录 hypothesis，做一次低影响确认或补充侦查，再决定是否转成新 observation、next_action 或建议新增 Skill。

运行产物与源文件边界：

- `SKILL.md`、`references/`、`templates/` 和 `skills/` 是 Skill 源文件区域，运行时只读，禁止写入、覆盖、替换或把报告/证据/临时文件保存到这些目录。
- `templates/*.md` 只能作为只读模板读取；生成报告时必须渲染到 `reports/<系统名称>/...`，不得修改模板文件本身。
- 主代理启动测试前必须确定 `XSEC_RUN_ROOT`。未显式提供时，默认使用仓库下 `.xsec-runs/default/`；所有 `evidence/`、`reports/`、`tmp/`、`tools/`、`data/` 等路径都视为相对 `XSEC_RUN_ROOT`。
- `skills/xsec-jwt-security/wordlists/rockyou.txt` 是有意保留的一次下载长期复用字典缓存，不按运行产物处理。

证据分级要求：

- UI 可见类 finding：payload 应包含 `evidence_runbook: web-pentest-browser-flow/runbooks/05-evidence-browser.md` 和 `screenshot_required: true`；子代理确认后保存原始截图并用 `scripts/annotate_screenshot.py` 红框标注。
- API、passive、纯协议或无可视化类 finding：截图是优先证据但不是硬门禁；可以用 selected request/response、HAR slice、flow fingerprint、corpus-query 命中片段和短响应 preview 作为主证据，并写明 `screenshot_unavailable_reason`。
- 主代理验收 `validated` 报告时必须看到足以复现的证据链：关键截图或等价证据路径、Burp Raw 风格请求响应、触发条件、影响说明和脱敏策略。
- 未发现或阻断结果优先保存状态截图；如果没有可视化界面，not-found/blocked 文档必须引用能说明覆盖范围或阻断原因的最小证据路径。

## 适用场景

- 需要对 Web 目标做分阶段安全测试。
- 需要根据页面/流量观察结果按需启用漏洞 Skill，而不是一次性跑完所有测试。
- 需要主代理实时维护状态、问题清单、已验证战果和下一步队列。
- 需要把浏览器流量采集作为可替换插件接入测试流程。
- 需要多个子代理并行，但每个子代理只执行被触发的一个漏洞 Skill。

## 渐进式披露

先判断自己当前角色，只读取对应文件：

| 当前角色/任务 | 读取 |
| --- | --- |
| 主代理：确认目标、做基线 scout、读取注册表、按观察信号触发漏洞 Skill、分配子代理、维护状态账本、汇总报告 | `references/main-agent.md` |
| 漏洞测试子代理：已经收到 `vulnerability_skill`、`agent`、`proxy`、`evidence_dir`、`activation_reason` 等任务 payload，需要生成发现/未发现文档 | `references/vulnerability-subagent.md` |
| 浏览器/抓包/flow 归一化/证据复现 | `web-pentest-browser-flow/SKILL.md`；子代理执行浏览器操作时再读取 `web-pentest-browser-flow/references/subagent-browser-operator.md` |
| 新增或调整漏洞 Skill 激活条件、场景 playbook、解锁输出 | `config/vulnerability-skills.yaml`；同步更新对应 Skill 的 `## 编排适配` |

不要同时读取主代理和子代理详细说明，除非当前任务确实跨越两个角色。主代理创建任务 payload 时只需要主代理说明；子代理执行任务时只需要子代理说明、被分配的漏洞 Skill 和 browser traffic adapter。

browser traffic adapter 可以替换，但必须能向编排层返回这些归一化输出：

- compact JSON summary。
- forms、actions、routes 和 page signals。
- API inventory path。
- request corpus path。
- passive findings path。
- flow path。
- browser state path。
- evidence paths。
