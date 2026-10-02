# Web 安全测试编排 Skill

`x-sec-agent` 是上级调度 skill。它负责 Web 安全测试的流程编排、漏洞 Skill 按需触发、子代理分配、实时进度、问题清单和战果列表。

浏览器点击、Playwright 交互、mitmproxy 流量采集和 flow 归一化由可插拔 adapter 提供。默认 adapter 是：

```yaml
adapters:
  browser_traffic:
    id: "web-pentest-browser-flow"
    path: "web-pentest-browser-flow"
```

## 核心思想

- 先观察，再触发；不要启动时一股脑跑完所有漏洞 Skill。
- 顶层 `skills/` 下所有 Skill 都要通过 `## 编排适配` 暴露适用场景、触发信号、测试前置环境、必需工件、解锁输出和阻断条件。
- `config/vulnerability-skills.yaml` 用 `scenario_playbooks` 描述常见路线，用 `activation.requires_environment` 控制是否真的派发子代理。
- `autonomy.default_level` 默认为 `guided`：注册表仍是正式派发路径，但主代理可以把未覆盖的新线索写入 `hypothesis_queue`，做低影响补证后再转成 observation、next_action 或新增 Skill 建议。
- 测试初期必须先做并行侦查：站点画像、API 路径发现、登录入口归集，以及按画像条件执行 DirSearch。
- 所有浏览器、DirSearch、弱口令和验证流量都必须经过 browser traffic adapter 的 proxy/passive hook，敏感信息命中自动落盘。
- 漏洞 Skill 必须通过 `activation` 条件启用。
- 每个被触发的漏洞 Skill 都开一个独立子代理；前序节点只通过 observations/wins 解锁后续节点，不代表后续节点已经确认存在漏洞。
- 子代理只围绕被分配的一个 Skill 工作，但可按 payload 的 `autonomy` 预算做 compact corpus-query、同源只读请求或小范围控件探测来补齐当前 Skill 证据。
- 浏览器流量采集是插件，不读取漏洞注册表，不决定子代理分配。
- 每个已验证问题和每个战果都必须引用 evidence path 或来源 artifact。
- 已发现漏洞和未发现漏洞都必须落 Markdown 文档，并分别存储；UI 类问题优先截图和红框标注，API/passive/协议类问题可用 selected request/response、HAR slice、flow fingerprint 或 corpus-query 命中作为等价证据。

## 快速流程

1. 确认测试目标 URL。
2. 使用 browser traffic adapter 启动 proxy/passive hook，并做 scout，生成 forms/actions/routes/API inventory/request corpus/passive findings。
3. 并行启动侦查子代理：站点画像、API 路径发现、登录入口归集；server_script 或 unknown 站点执行 Web 根路径 DirSearch，Vue/React 等 SPA 跳过 Web 根路径 DirSearch。
4. 对发现的 API base path 或接口目录执行 API DirSearch。
5. 如果提供了测试账号密码，直接登录并保存 browser state；否则在发现登录框、认证 API 或后台登录入口后触发预算化凭据审计。
6. 根据 `config/vulnerability-skills.yaml` 的 `scenario_playbooks` 识别当前路线，再用每个 Skill 的 activation、artifacts、environment 和 scope 条件决定是否触发。
7. 子代理使用独立 proxy、browser state、flow、passive findings 和 evidence 目录执行被分配的漏洞 Skill。
8. 子代理真实发现 UI 类漏洞后截图、红框标注重点位置，并生成 `reports/<系统名称>/<漏洞名称>.md`；API/passive/协议类问题保存等价证据路径并说明不可截图原因。
9. 子代理未发现漏洞时生成 `reports/<系统名称>/not-found/<漏洞名称>.md`；优先保存状态截图，无法截图时引用覆盖范围或阻断原因证据。
10. 编排层持续更新 `evidence/orchestrator/status.json`。
11. 收尾前复核 passive findings，按对应 passive Skill 判断敏感信息泄露并生成报告。
12. 最后调用漏洞组合 Skill，判断多个问题或战果是否能闭合成更高风险链路。
13. 对已确认 finding 做 evidence 复现并输出报告。

## 配置

复制或维护：

```bash
cp config/vulnerability-skills.yaml config/vulnerability-skills.local.yaml
```

当前配置把 35 个漏洞测试 Skill 放入 `vulnerability_skills`，把 `xsec-passive-scanning` 和 `xsec-vulnerability-chain-analysis` 放入 `post_processors`，合计覆盖顶层 `skills/` 下的所有 37 个 Skill。新增漏洞 Skill 时，在 `vulnerability_skills` 下追加条目，并同步补该 Skill 的 `## 编排适配`。未触发或环境不满足的 enabled Skill 保持 idle/blocked；未注册或 disabled 的 Skill 只能记录为建议，不会启动子代理。

### 自由度配置

`config/vulnerability-skills.yaml` 的 `autonomy` 控制 Agent 可主动补证的范围：

- `conservative`：只按注册表派发，缺少 artifact 时等待。
- `guided`：默认模式，允许低影响补证，例如 compact corpus-query、一次同源只读请求、小范围控件探测或 API 文档可访问性确认。
- `aggressive_authorized`：仅在用户明确授权时使用，允许更宽的低速率多分支补证，但仍受 scope、低影响、proxy/passive hook 和禁止破坏性动作约束。

弱口令节点现在按 `credential_audit_policy` 执行预算化凭据审计，默认小预算、单线程、命中即停；全量用户名枚举、大字典、喷洒、预算外尝试和高并发都需要显式授权。

## 渐进式披露

- 主代理读取 `references/main-agent.md`。
- 漏洞测试子代理读取 `references/vulnerability-subagent.md`。
- 浏览器操作、抓包、flow 归一化和证据复现再读取 `web-pentest-browser-flow/SKILL.md` 或其子代理操作指南。

顶层 `SKILL.md` 只做角色路由和边界声明，避免把主代理和子代理的详细流程一次性加载进上下文。

## 评估用例

`evals/evals.json` 保存了 9 个基础用例，用来检查 skill 是否真的做到：

- 发现登录框后才启用弱口令测试。
- 弱口令成功后记录问题和战果，再按注册状态决定是否启用权限/数据泄露测试。
- 浏览器流量采集通过 adapter 可替换，不把调度职责放回采集插件。
- 发现/未发现结果分别生成 Markdown 文档；UI 类发现必须截图并红框标注，API/passive/协议类发现可使用等价证据路径。
- passive hook 命中会进入收尾复核；组合漏洞 Skill 会在最终报告前被尝试调用。
