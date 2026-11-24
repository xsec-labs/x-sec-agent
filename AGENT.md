# xSecAgent 维护指南

## 项目是什么

xSecAgent 是一套面向 Web 安全测试的 skill 编排项目。它不是“启动后把所有漏洞都跑一遍”的扫描器，而是一个**主 Agent 管理树状任务、按需派发子 Agent** 的调度系统。浏览器与抓包已由本系统 MCP 接管（所有 Agent 共享全部浏览器与网络上下文，页面分组只做路由归因），本 skill 只负责编排：

1. 先确认目标和基础环境；用 MCP 浏览器（共享会话）做 scout，抓包用浏览器 network 工具。
2. 再做站点画像、API 路径发现、登录面归集、必要的目录扫描和浏览器 scout。
3. 把浏览器流量、DirSearch 结果、request corpus、API inventory、passive 命中转成**共享发现**（`attack_path_finding_add`）。
4. 主 Agent 判断测试价值，用 `attack_path_node_create` 把值得测的发现建成树节点。
5. 每个节点用 `xsec_subagent_dispatch(node_id, browser_session_id)` 单独开一个子 Agent 执行测试；服务端同时生成路由归因用的 `page_group_id`，它不隔离页面。
6. 子 Agent 只测自己被分配的一个节点 + 一个 skill，输出 found/not-found 报告、MCP 截图证据、Burp Raw 风格请求响应，并把新发现回填共享知识库、`attack_path_node_update` 更新自己节点。
7. 主 Agent 读 `attack_path_list` + `attack_path_findings_list`，把新发现建成新节点，继续扩展树。
8. 收尾时复核 passive 命中，并进行组合漏洞链路分析，最后 `xsec_report_submit`。

核心目标是：让测试树像状态机一样渐进往外生长。比如先发现环境和目录，再发现登录框后建弱口令节点；提供账号或弱口令成功后解锁登录后节点；发现 AK/SK 后解锁云密钥复核；发现 AI 对话场景后解锁 LLM prompt security。树是权威状态源，存活在 MCP，桌面端「测试树」界面实时可视化。

## 主要目录

- `skills/`
  顶层专项 skill 目录。每个 skill 负责一类漏洞或一个处理入口。

- `SKILL.md`
  项目根目录的上级编排 skill 入口。负责读取路由索引和注册表、维护状态账本、按观察信号派发子代理、汇总报告。

- `config/vulnerability-skills.yaml`
  编排注册表。定义场景 playbook、侦查任务、漏洞 skill 激活条件、收尾处理器；`adapters.browser` 声明浏览器由 MCP 接管；`mcp_tools` 声明主 Agent 专属与共享工具。

- `references/routing-index.md`
  给模型读的路由索引，一行一个 Skill（信号 → Skill id）。由 `scripts/build_routing_index.py` 从 `config/vulnerability-skills.yaml` 生成，不要手改。

- `scripts/`
  `build_routing_index.py` 生成路由索引（`--check` 只检查是否过期），`test_build_routing_index.py` 是它和文档链接的测试。

- `references/main-agent.md`
  主 Agent 执行指南。描述如何用 MCP 管理测试树、recon、建节点、派子 Agent、页面分组归因和收尾。

- `references/vulnerability-subagent.md`
  漏洞测试子 Agent 指南。描述子 Agent 如何登记会话、用 page_group 归因并操作完整共享浏览器、读单个 skill、回填共享发现、生成 found/not-found 报告。

- 浏览器与抓包由本系统 MCP 接管（Playwright 封装），不在本 skill 内实现。原 `web-pentest-browser-flow/` adapter 已废弃（不再被编排流程引用），目录标 deprecated 保留在仓库里作历史参考，没有删除。

- `Index.html`
  项目的可视化流程图，展示所有 skill 如何从上到下按场景解锁。

## 这轮已经完成的改造

### 1. 给所有 skill 增加编排适配

`skills/` 下 37 个 `SKILL.md` 都新增了 `## 编排适配` 小节，统一说明：

- 适用场景
- 触发信号
- 测试前置环境
- 必需工件
- 解锁输出
- 阻断条件

这个小节是编排层和子代理理解 skill 的第一入口。新增或修改 skill 时必须同步维护。

### 2. 重构编排注册表

`config/vulnerability-skills.yaml` 已升级为 `version: 2`。

当前结构：

- `scenario_playbooks`: 8 个常见场景路线图
- `vulnerability_skills`: 35 个漏洞测试节点
- `post_processors`: 2 个收尾节点
- `recon`: 初期侦查子代理
- `scheduler`: 子代理并发和队列策略
- `orchestration_model`: 节点/发现 payload 契约
- `adapters.browser`: 声明浏览器由 MCP 接管（完整共享会话 + 页面分组路由归因）
- `mcp_tools`: 主 Agent 专属工具与共享工具（树/发现/子 Agent/页面分组）

35 个漏洞测试节点 + 2 个收尾节点 = 覆盖顶层 `skills/` 下全部 37 个 skill。

### 3. 更新 orchestrator 文档

已更新：

- `SKILL.md`
- `README.md`
- `references/main-agent.md`
- `references/vulnerability-subagent.md`
- `examples/status-ledger.sample.json`
- `evals/evals.json`

主代理现在明确按 `scenario_playbooks` 理解场景，但真正派发必须满足：

- skill 已注册且 `enabled: true`
- observation 命中 `activation.any_signals`
- `activation.requires_artifacts` 对应工件存在
- `activation.requires_environment` 描述的环境真实存在
- 触发条件满足
- 没有全局阻断信号

### 4. 新增可视化流程图

新增 `Index.html`，用一个静态 HTML 页面展示从上到下的完整 skill 编排流程。页面包含所有 37 个 skill，并按阶段展示触发条件和前置环境。

已用 Playwright 验证：

- HTML 能正常渲染
- 桌面与移动首屏可读
- 控制台 0 errors
- 页面中 37 个 skill 无遗漏

## 当前 skill 覆盖关系

`vulnerability_skills` 中的 35 个测试节点：

- `weak-pass-check`
- `account-enumeration`
- `brute-force-protection`
- `captcha-otp-defect`
- `api-interface-exposure`
- `client-hardcoded-secret`
- `cloud-secret-leakage`
- `object-storage-bucket`
- `config-backup-leakage`
- `directory-sensitive-leakage`
- `middleware-unauth-management`
- `shiro-attack-detection`
- `unauth-access`
- `version-info-exposure`
- `transport-security`
- `cookie-security-flags`
- `cors-misconfiguration`
- `sql-error-info-leak`
- `error-path-leakage`
- `internal-network-leakage`
- `sql-injection`
- `xss`
- `ssrf`
- `path-traversal`
- `file-download-access-control`
- `file-upload-security`
- `llm-prompt-security`
- `browser-sensitive-storage`
- `jwt-security`
- `session-token-invalidation`
- `access-control-idor`
- `password-policy`
- `password-storage-return`
- `insecure-crypto`
- `csrf-protection-missing`

`post_processors` 中的 2 个收尾节点：

- `passive-sensitive-review` -> `skills/xsec-passive-scanning`
- `vulnerability-chain-analysis` -> `skills/xsec-vulnerability-chain-analysis`

## 新增 skill 时必须同步修改哪里

新增一个 skill 不只是加一个目录。必须同步以下文件。

### 必改 1：新增 skill 目录

在 `skills/` 下新增目录：

```text
skills/xsec-new-skill/
├── SKILL.md
└── source_files.json    # 可选，但建议有
```

`SKILL.md` front matter 至少包含：

```markdown
---
name: xsec-new-skill
description: 这里写清楚该 skill 解决什么漏洞、什么时候应该使用。
---
```

正文必须包含 `## 编排适配`：

```markdown
## 编排适配

- 适用场景：什么业务/页面/API/流量场景下适用。
- 触发信号：`some_signal_detected`、`another_signal_detected`。
- 测试前置环境：必须具备什么环境才能测试，例如登录态、登录框、上传控件、AI 对话框、测试手机号、第二账号、对象 ID、可重放请求等。
- 必需工件：`request_corpus`、`api_inventory`、`browser_state`、`passive_findings` 等。
- 解锁输出：`new_signal_detected`、`post_login_surface_available` 等。
- 阻断条件：什么情况下不能测，只能 blocked/not_found。
```

### 必改 2：注册到 vulnerability-skills.yaml

编辑：

```text
config/vulnerability-skills.yaml
```

如果它是普通漏洞测试 skill，追加到 `vulnerability_skills`。

模板：

```yaml
- id: new-skill
  name: 新增漏洞测试名称
  path: skills/xsec-new-skill
  status: registered
  enabled: true
  priority: 60
  default_agent: new-skill
  task_template: 启动子代理执行 新增漏洞测试名称；读取 skills/xsec-new-skill/SKILL.md 的编排适配和测试方法，只围绕 activation_reason 对应证据做最小化验证，并生成 found/not-found 报告。
  activation:
    phase: post_auth
    any_signals:
    - new_surface_detected
    - new_candidate_detected
    requires_artifacts:
    - request_corpus
    - browser_state
    requires_environment: 必须有有效登录态、可重放请求和测试数据；没有这些环境时返回 blocked，不启动子代理。
  output_contract:
  - compact JSON summary
  - observations
  - finding candidates path
  - validated issue paths
  - not-found report paths
  - annotated screenshot paths when browser evidence exists
  - passive findings path
  - unlocked signals
  unlocks_on_success:
  - new_issue_validated
  - downstream_signal_detected
```

如果它是收尾类、路由类或组合分析类 skill，追加到 `post_processors`，不要放进 `vulnerability_skills`。

### 必改 3：更新 scenario_playbooks

同一个 YAML 里检查 `scenario_playbooks`。

新增 skill 属于哪个场景，就把它加入对应 `unlock_sequence`。常见场景包括：

- `anonymous_public_site`
- `login_surface_without_credentials`
- `provided_credentials_or_weak_success`
- `api_document_or_api_base_found`
- `file_surface_found`
- `ai_conversation_found`
- `secret_or_sensitive_hook_found`

如果现有 playbook 不合适，就新增一个 playbook：

```yaml
- id: new_business_surface_found
  description: 发现新的业务测试面。
  entry_signals:
  - new_surface_detected
  unlock_sequence:
  - new-skill
  - related-downstream-skill
```

注意：playbook 只是路线提示，不是执行清单。真正派发仍然看每个 skill 的 `activation`。

### 必改 4：重新生成路由索引

`references/routing-index.md` 是 `config/vulnerability-skills.yaml` 的生成物（信号 → Skill 一行一个），主 Agent 靠它判断该派发哪个 Skill。改完 yaml 后在本仓库根目录运行：

```bash
python3 scripts/build_routing_index.py
```

不要手改索引；`python3 -m unittest discover -s scripts -p 'test_*.py'` 会校验索引与 yaml 一致（仓库没有 CI，提交前自己跑一遍）。

如果这个 skill 会改变流程，例如成功后解锁登录后测试、文件测试、云密钥复核、组合链路分析，也要在 `main-agent.md` 的“触发判断”一节补一句。

### 必改 5：更新子代理说明中的特殊要求

大多数 skill 不需要改子代理通用指南。

但如果新增 skill 有特殊交付要求，例如：

- 必须双账号
- 必须测试手机号
- 必须 AI 对话场景
- 必须上传无害测试文件
- 必须使用外部 OOB 监听
- 必须只读云厂商验证
- 必须延后到测试收尾阶段

则编辑：

```text
references/vulnerability-subagent.md
```

加入对应注意事项，避免子代理误测。

### 必改 6：更新 Index.html

编辑：

```text
Index.html
```

在页面内的 `stages` 数据中，把新 skill 放进合适阶段：

```js
["xsec-new-skill", "新增漏洞测试名称", "触发：new_surface_detected", "环境：必须具备什么测试条件"]
```

如果新增 skill 代表一个新的阶段，也可以新增 stage，但要保证页面仍然是从上到下的流程图。

更新后必须确认页面中 skill 总数正确。

### 建议改 7：更新 README 和 evals

如果新增 skill 改变了 orchestrator 的核心流程，应同步更新：

```text
README.md
evals/evals.json
examples/status-ledger.sample.json
```

只有新增普通专项 skill，且不改变主流程时，README 可以不改；但 evals 中如果有对应场景，应该补用例。

## 新增 skill 的完整流程

### Step 1：创建目录和 SKILL.md

```bash
mkdir -p skills/xsec-new-skill
```

写 `skills/xsec-new-skill/SKILL.md`，包含 front matter、`## 编排适配` 和具体测试方法论。

### Step 2：定义观察信号

先想清楚它靠什么触发。

好的信号示例：

- `login_form_detected`
- `authenticated_session_obtained`
- `file_upload_api_detected`
- `llm_chat_interface_detected`
- `passive_secret_match`
- `jwt_token_detected`
- `id_like_resource_paths_detected`

不要用模糊信号：

- `maybe_has_bug`
- `interesting`
- `needs_test`

信号应该描述“观察到什么”，不要直接描述“漏洞已存在”。

### Step 3：定义前置环境

必须写清楚什么环境存在才可以测。

示例：

- 弱口令：必须发现登录框或认证 API，并且已确认字典、速率、锁定策略。
- 后台测试：必须已登录后台或发现后台入口。
- 越权测试：必须有登录态；水平越权最好有两个同级账号；垂直越权需要不同角色账号。
- 文件上传：必须有上传控件/API、测试账号和无害测试文件。
- 文件下载：必须有自有测试文件或第二账号测试文件。
- AK/SK：必须有疑似凭据和来源证据；验证只能用只读或隔离资源。
- AI 对话：必须有聊天/RAG/模型接口；只能发无害测试提示。
- OTP/短信：必须有测试手机号/邮箱或测试环境接收端。

### Step 4：注册 YAML

把 skill 加到 `vulnerability_skills` 或 `post_processors`。

注意字段：

- `id`: 短 slug，供编排引用
- `path`: 指向真实 skill 目录
- `priority`: 越高越早派发
- `activation.any_signals`: 触发信号
- `activation.requires_artifacts`: 必需工件
- `activation.requires_environment`: 必需环境
- `unlocks_on_success`: 成功后写回的新信号

### Step 5：更新 playbook

把新 skill 放入合适场景的 `unlock_sequence`。如果是全新测试面，新增 playbook。

### Step 6：重新生成路由索引

运行 `python3 scripts/build_routing_index.py`；只有索引表达不了的触发关系才在 `references/main-agent.md` 的“触发判断”里补一句。

### Step 7：更新可视化页面

在 `Index.html` 的 `stages` 里加入新 skill。

### Step 8：跑校验

运行：

```bash
python3 - <<'PY'
from pathlib import Path
import yaml, json

cfg = Path('config/vulnerability-skills.yaml')
data = yaml.safe_load(cfg.read_text())
root = cfg.parent.parent

missing = []
for s in data.get('vulnerability_skills', []):
    if not (root / s['path']).resolve().exists():
        missing.append((s['id'], s['path']))
    for key in ['phase', 'any_signals', 'requires_artifacts', 'requires_environment']:
        if key not in s.get('activation', {}):
            missing.append((s['id'], f'missing activation.{key}'))

for pp in data.get('post_processors', []):
    if not (root / pp['path']).resolve().exists():
        missing.append((pp['id'], pp['path']))
    if 'requires_environment' not in pp.get('activation', {}):
        missing.append((pp['id'], 'missing activation.requires_environment'))

skill_docs = list(Path('skills').glob('*/SKILL.md'))
missing_adapt = [str(p) for p in skill_docs if '## 编排适配' not in p.read_text(encoding='utf-8')]

json.loads(Path('evals/evals.json').read_text())
json.loads(Path('examples/status-ledger.sample.json').read_text())

print('skill_docs:', len(skill_docs))
print('registered_nodes:', len(data.get('vulnerability_skills', [])) + len(data.get('post_processors', [])))
print('missing_paths_or_fields:', missing)
print('missing_adapt_sections:', missing_adapt)
PY
```

再运行：

```bash
git diff --check
```

### Step 9：检查 Index.html 是否覆盖全部 skill

```bash
python3 - <<'PY'
from pathlib import Path

html = Path('Index.html').read_text(encoding='utf-8')
skills = []

for p in sorted(Path('skills').glob('*/SKILL.md')):
    txt = p.read_text(encoding='utf-8')
    name = ''
    if txt.startswith('---'):
        fm = txt.split('---', 2)[1]
        for line in fm.splitlines():
            if line.startswith('name:'):
                name = line.split(':', 1)[1].strip()
                break
    skills.append(name or p.parent.name)

missing = [s for s in skills if s not in html]
print('skills:', len(skills))
print('missing_from_index:', missing)
PY
```

### Step 10：可选，用浏览器复核 Index.html

如果本地有 `npx`，可用 Playwright CLI skill 或临时 HTTP 服务检查。

```bash
python3 -m http.server 8765 --bind 127.0.0.1
```

然后打开：

```text
http://127.0.0.1:8765/Index.html
```

确认：

- 桌面布局没有文字重叠
- 移动布局可读
- 控制台没有 errors
- 新 skill 出现在正确阶段

## 修改已有 skill 的规则

修改已有 skill 时，同样要思考是否影响编排。

如果只是改测试方法细节：

- 改对应 `skills/<skill>/SKILL.md`
- 通常不需要改 YAML

如果新增触发条件：

- 改 `SKILL.md` 的 `## 编排适配`
- 改 `vulnerability-skills.yaml` 的 `activation.any_signals`
- 重新生成路由索引；索引表达不了的关系才改 `main-agent.md` 的“触发判断”
- 必要时改 `Index.html`

如果新增前置环境：

- 改 `SKILL.md` 的“测试前置环境”和“阻断条件”
- 改 YAML 的 `activation.requires_environment`
- 必要时改子代理说明，避免误测

如果新增解锁输出：

- 改 `SKILL.md` 的“解锁输出”
- 改 YAML 的 `unlocks_on_success`
- 如会影响路线，改 `scenario_playbooks`
- 如会影响示例，改 `status-ledger.sample.json`

## 命名约定

- 顶层 skill 目录建议用 `xsec-<domain>`。
- YAML `id` 用短 slug，不一定要带 `xsec-`。
- 观察信号使用 snake_case，通常以 `_detected`、`_candidate`、`_available`、`_obtained`、`_validated` 结尾。
- 工件名称要和实际 evidence 路径或 adapter 输出保持一致，例如 `request_corpus`、`api_inventory`、`browser_state`、`passive_findings`。
- 不要把漏洞结论写成触发信号。触发信号应表示“观察到了测试面”，结论由子代理验证后输出。

## 最后检查清单

新增或修改 skill 后，提交前检查：

- [ ] `skills/<skill>/SKILL.md` 有 `## 编排适配`
- [ ] `vulnerability-skills.yaml` 有对应节点或收尾处理器
- [ ] `references/routing-index.md` 已随 yaml 重新生成（`python3 scripts/build_routing_index.py`；`python3 -m unittest discover -s scripts -p 'test_*.py'` 会校验两者一致）
- [ ] `activation.any_signals` 是观察信号，不是漏洞结论
- [ ] `activation.requires_artifacts` 写清楚必需工件
- [ ] `activation.requires_environment` 写清楚环境门槛
- [ ] `unlocks_on_success` 能被后续节点消费
- [ ] `scenario_playbooks` 已同步
- [ ] `Index.html` 已展示新 skill
- [ ] YAML/JSON 解析通过
- [ ] `git diff --check` 通过
- [ ] 若改了可视化页面，浏览器桌面和移动都检查过
