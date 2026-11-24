---
name: xsec-shiro-attack-detection
description: Apache Shiro rememberMe 弱 Key 与利用链检测方法论，用于确认 Shiro 存在、验证常见弱 Key，并做 Gadget/回显链检测。最常见触发时机是 passive hook 流量中发现 Shiro rememberMe 或 deleteMe Cookie 信号，但这只是参考信号而非前置门槛；用户直接提到 Shiro、rememberMe、deleteMe、Shiro-550、CVE-2016-4437、Shiro 弱口令、Shiro 弱 Key 或 Shiro 利用链检测，或从技术栈判断目标可能是 Java + Shiro 时，也应使用本 skill。
---

# Shiro 弱 Key 与利用链检测

## 编排适配

先读 [运行边界与证据口径](../../references/security-boundaries.md)。在分配的节点、预算和低影响约束内执行；`scope_policy` 只做资产归因，新发现的目标记录来源即可，不因 `in_scope=false` 停止；证据保留观察到的原始值，报告与委派只取证明问题所需的最小片段。

- 适用场景：passive hook 在请求或响应头中发现 `rememberMe` Cookie、`rememberMe=deleteMe` 或 `deleteMe` 标记，需要判断目标是否存在 Apache Shiro rememberMe 反序列化风险。
- 触发信号：`passive_shiro_cookie_detected`、`shiro_rememberme_cookie_observed`、`shiro_deleteme_cookie_observed`。
- 测试前置环境：通常需要已有 `passive_findings` 中的 Shiro Cookie 命中；弱 Key 检测需 ShiroAttack2 CLI 或等价工具。
- 参考工件：`passive_findings`、`request_corpus`、`flow`、`target`、`proxy`、`shiro_attack_cli`、`shiro_key_wordlist`。
- 解锁输出：`shiro_framework_confirmed`、`shiro_weak_key_detected`、`shiro_gadget_chain_detected`、`shiro_deserialization_rce_candidate`、`vulnerability_chain_input`。
- 建议阻断（可低影响补齐时先补证再测）：未发现 passive Shiro Cookie 信号、缺少可重放目标 URL、工具不可用且无法在本地准备、目标被 WAF/challenge 阻断或验证会造成业务影响。

## 何时测试

最常见的触发方式是 passive 扫描在请求或响应头中观察到以下任一证据，这时直接判断测试价值很高：

- 请求头或响应头中出现 `rememberMe=`。
- 响应头中出现 `rememberMe=deleteMe`。
- Cookie 相关头部中出现 `deleteMe`。

但这只是参考信号，不是前置门槛。用户直接要求测试 Shiro、或从技术栈/框架指纹/错误栈判断目标很可能是 Java + Shiro，即使还没有 passive Cookie 命中，主 Agent 也可以凭判断直接派发——先通过浏览器/代理采集一轮流量确认框架存在，再继续后面的弱 Key 和利用链验证，不必卡在等 passive 命中。真走到"确认目标不是 Shiro 或拿不到任何相关证据"时再收尾为 not-found，不要预先假设测不了。

## 测试目标

判断目标是否存在 Shiro rememberMe 反序列化风险，生成 found/not-found 报告。真实的依赖关系只有一条：没有确认弱 Key 就没有可用的利用链，所以 Gadget/回显链检测必须在弱 Key 命中之后——这是技术上的硬约束，不是编排规定。其余部分（先核对证据来源还是先跑 detect、要不要同时核对多个 passive 命中）按你的判断安排。

## 工具准备

可使用 ShiroAttack2 CLI。参考来源：`https://github.com/SummerSec/ShiroAttack2/blob/master/.claude/skills/shiro-attack-cli/SKILL.md`。

本 skill 内置 Shiro Key 字典：`wordlists/shiro-keys.txt`，共 203 个候选 Key。弱 Key 检测必须优先使用这份字典；不要自动下载或扩展其他字典，除非用户明确要求。

本地没有 JAR 时，优先在子代理独立工具目录准备：

```bash
RUN_ROOT="${XSEC_RUN_ROOT:-.xsec-runs/default}"
mkdir -p "$RUN_ROOT/tools/shiro-attack" "$RUN_ROOT/data"
```

JAR 可从 ShiroAttack2 Releases 下载到 `tools/shiro-attack/`。执行时使用：

```bash
RUN_ROOT="${XSEC_RUN_ROOT:-.xsec-runs/default}"
JAR="$RUN_ROOT/tools/shiro-attack/shiro_attack-5.1.1-all.jar"
CP="com.summersec.attack.CLI.MainCLI"
```

ShiroAttack2 的 `crack` 命令默认读取运行目录下的 `data/shiro_keys.txt`。执行前把内置字典复制到该位置：

```bash
SHIRO_SKILL_DIR="skills/xsec-shiro-attack-detection"
RUN_ROOT="${XSEC_RUN_ROOT:-.xsec-runs/default}"
mkdir -p "$RUN_ROOT/data"
cp "$SHIRO_SKILL_DIR/wordlists/shiro-keys.txt" "$RUN_ROOT/data/shiro_keys.txt"
cd "$RUN_ROOT"
```

流量可被捕获与复现。若用户提供了抓包代理，可用 CLI 的 `--proxy` 参数经过它（下方示例中的 `$PROXY`）；未提供时直接执行并完整记录请求/响应作为证据。浏览器可见步骤用 MCP 浏览器 network 抓包留证。

## 参考命令

下面按"核对证据 → 确认框架 → 弱 Key → 利用链"的常见顺序给出可直接用的命令，不是必须照抄的脚本——可以调整顺序、跳过已经确认过的部分，或者用你更熟悉的等价工具。

### 1. 复核 passive 命中

从 `passive_findings` 中筛选：

- `signal` 为 `passive_shiro_cookie_detected`。
- `pattern_id` 为 `shiro-cookie` 或同类 Shiro Cookie 规则。
- `location` 为 `request_headers` 或 `response_headers`。
- `target_skill` 指向 `../skills/xsec-shiro-attack-detection`。

按 `host + path + pattern_id + match_hash + location` 去重，保留原始证据集：时间、路径、状态码、request_id、完整 headers、原始命中值、响应内容和 flow path。

### 2. 确认 Shiro 行为

对 passive 命中的同 host 选择一个低影响 URL，优先使用触发 Cookie 的原路径或首页。通过 ShiroAttack2 detect 验证：

```bash
java -cp "$JAR" "$CP" detect \
  -u "$TARGET_URL" \
  --cbc \
  --proxy "$PROXY" \
  --timeout 10
```

若 CBC 未命中且目标表现为较新 Shiro，可再尝试 GCM：

```bash
java -cp "$JAR" "$CP" detect \
  -u "$TARGET_URL" \
  --gcm \
  --proxy "$PROXY" \
  --timeout 10
```

成功信号是工具确认存在 Shiro 框架，或响应稳定出现 `rememberMe=deleteMe`。如果 passive 命中充分但主动 detect 未确认，只能记录为 Shiro 指纹候选，不进入弱 Key 结论。

### 3. 弱 Key 检测

弱 Key 检测只验证本 skill 内置 203-key 字典是否命中，不做大规模扩展爆破。工作目录需要存在由 `wordlists/shiro-keys.txt` 准备出的 `data/shiro_keys.txt`。

以下命令执行，并完整记录请求/响应作为证据（如用户提供 `$PROXY` 则经其转发）：

```bash
java -cp "$JAR" "$CP" crack \
  -u "$TARGET_URL" \
  --cbc \
  --timeout 15
```

必要时对 GCM 重复一轮：

```bash
java -cp "$JAR" "$CP" crack \
  -u "$TARGET_URL" \
  --gcm \
  --timeout 15
```

判断：

- 找到 Key：记录为 `shiro_weak_key_detected`，报告和共享发现中写入完整原始 Key，同时可附 hash 便于去重。
- 未找到 Key：记录为 not-found 或 `shiro_framework_confirmed_without_weak_key`，不得扩大到其他字典、长时间爆破或分布式尝试。

### 4. 利用链检测

只有同时满足以下条件才允许执行：

- 已确认弱 Key。
- 目标 URL、proxy、AES 模式、Key 均已确认。

以下命令执行，并完整记录请求/响应作为证据（如用户提供 `$PROXY` 则经其转发）：

```bash
java -cp "$JAR" "$CP" exec \
  -u "$TARGET_URL" \
  -K "$SHIRO_KEY" \
  -c "echo xsec-shiro-probe" \
  --cbc \
  --timeout 15 \
  --json
```

使用 `whoami` / `id` 这类低影响命令，并在报告中保留原始输出。工具自动发现 Gadget/回显链时，记录链名、回显方式、AES 模式、完整原始 payload 和请求证据。


## 关键判断点

- `rememberMe` 或 `deleteMe` 是触发信号，不等于漏洞成立。
- Shiro 存在不等于存在 Shiro-550；必须有弱 Key 或等价密钥验证证据。
- 弱 Key 命中但未做命令验证，仍可作为弱 Key 风险成立；不要把它夸大成已验证 RCE。
- Gadget/回显链验证成功，才可表述为反序列化命令执行风险。
- detect/crack/exec 均应走 proxy，确保 passive hook、flow 和 evidence 能复现。

## 证据链要求

- passive 触发证据：`passive_findings` 中的 request_id、host/path、location、pattern_id、match_hash 和 preview。
- Shiro 行为证据：detect 输出、响应头中的 Cookie 片段或 `deleteMe` 行为。
- 弱 Key 证据：工具命中记录、AES 模式、完整原始 Key、Key hash、验证时间和目标 URL。
- 利用链证据：记录无害命令输出、Gadget 链名、回显方式、请求/响应短片段。
- 截图证据：优先截图能展示目标入口、响应头展示面、工具输出摘要或报告页面；纯 API 场景可说明无可视化页面并引用 selected request/response。

## 报告表达模板

**漏洞名称**：Apache Shiro rememberMe 弱 Key 与反序列化风险

**漏洞描述**：测试中先通过被动流量发现目标返回或携带 Shiro `rememberMe` / `deleteMe` Cookie，再验证 Shiro rememberMe 机制和常见弱 Key。若弱 Key 命中，攻击者可能构造受信任的 rememberMe 数据；若进一步确认可用 Gadget/回显链，则可能造成远程命令执行。

**验证方式**：基于 passive finding 选择低影响 URL，使用 ShiroAttack2 CLI 依次执行 Shiro 行为确认、常见 Key 验证。

**影响说明**：弱 Key 会削弱 Shiro rememberMe 加密保护，可能被用于构造恶意序列化数据。实际影响取决于 Shiro 版本、AES 模式、依赖库 Gadget、回显条件和目标运行权限。

**修复建议**：升级 Apache Shiro 至安全版本，禁用不必要的 rememberMe，替换为高强度随机 Key，清理默认 Key，统一重启使旧 Cookie 失效，并结合依赖治理移除高风险 Gadget 依赖。

**复测建议**：复测时应先确认 passive 不再出现异常 `deleteMe` 行为，再验证旧弱 Key 不再命中；如曾验证利用链，应确认同一低影响命令验证已失败且无旁路入口。
