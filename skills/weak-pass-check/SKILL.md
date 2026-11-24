---
name: weak-pass-check
description: 针对已发现登录入口的凭据审计 skill。用于弱口令、默认凭据、泄露凭据复核和登录防护边界验证。
---

# 弱口令检测技能

本技能自动完成登录面侦察、凭据来源整理、全量凭据尝试和证据输出，用于对登录表单进行弱口令或默认凭据审计。

## 快速上手
1. 用户提供目标 URL。
2. 用浏览器工具打开该 URL，分析登录表单和网络请求。
3. 收集目标信息（域名、组织名、邮箱、手机号、关键词等），用于生成社工字典。
4. 创建输出目录：`$XSEC_RUN_ROOT/agents/weak-pass-check/<hostname>_<port>/`（例如 `.../example.com_443/`）。
5. 将侦察结果保存至该输出目录的 `recon_results.md`。
6. 运行 `scripts/social_engineering_dict.py` 生成社工字典。
7. 基于 `scripts/example.py` 生成定制化的 `brute_force.py`。
8. 先以 `--test` 模式验证请求逻辑，再执行全量弱口令/密码喷洒，保证在有限时间内跑完整个字典。

## 编排适配

先读 [运行边界与证据口径](../../references/security-boundaries.md)。在分配的节点、预算和低影响约束内执行；`scope_policy` 只做资产归因，新发现的目标记录来源即可，不因 `in_scope=false` 停止；证据保留观察到的原始值，报告与委派只取证明问题所需的最小片段。


- 适用场景：已发现登录页面、密码字段、认证 API 或后台登录入口，需要在速率、锁定和验证码边界内对全量字典执行弱口令、默认凭据或泄露凭据审计。
- 触发信号：`login_form_detected`、`password_field_detected`、`auth_endpoint_detected`、`admin_login_form_detected`、`dirsearch_login_route_detected`。
- 测试前置环境：目标通常需要存在可交互登录框或可重放认证接口；payload 建议给出 `max_threads`、`delay_seconds`、`lockout_stop_condition`、验证码/锁定处理规则和允许的凭据来源。若用户已提供有效凭据并登录成功，本节点可跳过默认弱口令尝试。
- 参考工件：`evidence/recon/login-surfaces.json`、`forms/actions`、`认证请求样本`、`passive_findings`、`字典或用户提供凭据`。
- 解锁输出：`authenticated_session_obtained`、`post_login_surface_available`、`credential_weakness_validated`、`account_enumeration_candidate`。
- 建议阻断（可低影响补齐时先补证再测）：未发现登录入口、验证码/OTP/锁定策略不允许自动尝试、口令字典不可用、目标进入 challenge 或风险控制状态。

---

## 工作流程

### 阶段 0：环境准备
1. **创建输出目录**：在 `XSEC_RUN_ROOT/agents/weak-pass-check/` 下命名为 `<hostname>_<port>`（例如 `target.com_443`）。不要在 Skill 源目录下创建目标目录。
2. **检查依赖**：确保已安装 `requests`、`tqdm`、`pycryptodome`。若检测到图片验证码，需额外安装 `ddddocr`。
3. **初始化脚本**：将 `scripts/example.py` 复制到目标目录并命名为 `brute_force.py`。这是一个完整可运行的凭据审计框架——填写顶部 `[CONFIG]` 区域即可，其他模块在需要时修改（例如自定义响应解析、非标准验证码逻辑）。
4. **读取运行参数**：从 payload 或主代理状态读取运行配置，至少包含：
   - `max_threads`：默认 1；可按目标响应能力提高以在有限时间内跑完全量字典。
   - `delay_seconds`：默认 1.0 秒；遇 429/503、验证码或锁定信号时自动退避。
   - `lockout_stop_condition`：例如出现锁定提示、验证码升级、IP 风控或账号状态变化；命中即停，避免锁定真实账号。
   - `credential_sources`：使用的凭据来源，例如用户提供、目标前端泄露、默认凭据、社工字典、通用字典。
5. **全量执行原则**：默认对选定的用户名×密码字典做全量组合尝试，不做人为截断；命中有效凭据后立即停止。仅在锁定/验证码/风控等边界条件触发时降速或停止。

### 阶段 1：信息收集（侦察）
**目标**：收集构建有效登录请求所需的全部数据。

1. **入口点**：访问登录页面，记录精确的登录接口 URL、HTTP 方法（POST/GET）以及 Network 面板中的所有表单字段名。
2. **前端敏感信息发现**：对登录页面所有可访问的前端资源（JS、HTML、CSS、配置文件）逐一检索敏感信息，所有发现均记录至 `recon_results.md` 的「敏感信息」章节，并优先将泄露的账号/密码直接用于测试。
   - **覆盖范围**：
     - **JS 文件**：页面 `<script src>` 引用的所有外部脚本及内联 `<script>` 块。
     - **HTML 页面**：登录页及其 iframe、跳转页的原始 HTML 源码。
     - **CSS / 配置文件**：`config.js`、`env.js`、`settings.json`、`web.config` 等可直接访问的配置资源。
     - **Source Map**：检查 `.map` 文件（`main.js.map`、`chunk.js.map`），若存在则下载还原源码后重新检索。
   - **注释**（JS `//` / `/* */`、HTML `<!-- -->`、CSS `/* */`）：
     - 查找开发者遗留的测试账号、临时密码、调试开关。
     - 查找 `TODO`、`FIXME`、`HACK`、`DEBUG` 标注中的凭据或内部信息。
     - 查找被注释掉的旧接口地址或 API Key。
   - **硬编码凭据**：搜索 `password`、`passwd`、`pwd`、`secret`、`token`、`apikey`、`api_key`、`access_key`、`auth`、`credential` 等关键字，提取明文或 Base64 编码的值。
   - **内部接口泄露**：搜索 `http://`、`https://`、`/api/`、`/internal/`、`/admin/`、`/manage/`，发现隐藏管理后台或未授权接口。
   - **环境变量/配置对象**：搜索 `process.env`、`window.__CONFIG__`、`window._env_`、`globalConfig`、`APP_CONFIG`，提取运行时注入的密钥或服务地址。
3. **加密/编码**：检查 JavaScript 源码中的加密库。
   - RSA → `jsencrypt`、`JSEncrypt`、`setPublicKey` → 提取公钥。
   - AES → `crypto-js`、`CryptoJS.AES` → 提取 key/IV/模式。
   - SM2/SM4 → `sm-crypto` 库。
   - 详见 `references/encryption_patterns.md` 识别指南。
4. **验证码**：识别类型，**优先执行绕过检测**，以下顺序执行，一旦成功立即停止并记录策略，无需 OCR。

   #### Step A：参数删除绕过（最简单）
   从请求中完整移除验证码字段（常见字段名：`captcha`、`code`、`verifyCode`、`imageCode`、`checkCode`、`captchaCode`）后提交请求。
   - **判定**：若服务端返回"账号/密码错误"（而非"验证码错误/不能为空"），则验证码校验已被绕过，后续审计尝试**不传验证码字段**。

   #### Step B：空值绕过
   将验证码字段值设为空字符串 `""`、`null` 或 `000000`，提交请求。
   - **判定**：服务端未报验证码相关错误，则绕过成功，后续审计尝试**固定传空值**。

   #### Step C：Cookie / Session 绕过
   删除请求中所有与验证码相关的 Cookie 或 Header（常见名称：`captchaToken`、`verifySession`、`captchaId`、`JSESSIONID` 若验证码 session 与其绑定），重新提交登录请求。
   - **判定**：服务端未报验证码错误，则 Cookie 绑定已失效，绕过成功。

   #### Step D：验证码复用检测
   用浏览器正常获取一个验证码（记录其值），**用同一个验证码值连续发送 2-3 次请求**（不管密码对错，确保每次都是错误密码）。
   - **判定**：第 2、3 次请求服务端**未报验证码错误**（仅报密码错误），则验证码可复用，后续审计尝试**只需获取一次验证码**，反复使用，完全无需 OCR。
   - 复用脚本逻辑：初始获取一次验证码，每隔 N 次请求（可配置，建议 50-100 次）重新刷新一次。

   #### Step E：OCR 识别（最后手段）
   以上绕过均失败时，才启用 OCR：
   - **图片验证码**：使用 `ddddocr` 单例进行 OCR 识别，记录 `CAPTCHA_URL`。
   - **滑块验证码**：检查服务端 API 是否直接返回 `sliderCheckCode`（客户端校验）——若是，直接调用 API 获取校验码即可（参见示例）。

   #### 无初始验证码
   记录触发条件（例如"同一账号失败 3 次后触发"），审计脚本在检测到验证码触发后自动切换到上述检测流程。

   **侦察结论写入 `recon_results.md`**：记录验证码类型、已验证的绕过/复用策略、复用时建议的刷新间隔。
5. **响应分析**：精确识别响应体/状态码中的成功与失败标志。
   - 成功示例：响应体为 `ok` 或包含 `{"code":200}`。
   - 失败示例：响应包含 `"用户名或密码错误"`。
6. **用户名枚举漏洞检测**：使用 2-3 个不同的测试用户名（如 `__nonexist_abc__`、`admin`、`test`），固定错误密码，对比响应差异，判断是否存在用户名枚举漏洞。
   - **枚举漏洞判定**：若"用户名不存在"与"密码错误"返回的响应内容（提示文字、错误码、响应结构）存在可区分的差异，则确认存在用户名枚举漏洞。
   - **重要**：将检测结论（是否可枚举 / 区分标志字段及值）明确记录至 `recon_results.md` 的「用户名枚举」章节，供后续阶段决策字典策略。
   - 枚举漏洞示例（存在）：用户名不存在返回 `{"msg":"账号不存在"}` vs 密码错误返回 `{"msg":"密码错误"}`。
   - 无枚举漏洞示例：任何用户名均返回 `{"msg":"用户名或密码错误"}`，无差异。
7. **锁定策略**：使用明显错误的密码测试，观察连续失败是否导致账号锁定、触发验证码或 IP 封锁。
8. **记录文档**：将所有侦察结果保存至 `<target_folder>/recon_results.md`。

### 阶段 2：社工字典生成（情报转化）
**目标**：将阶段1收集到的所有情报转化为定制化的社工字典，大幅提高第一阶段命中率。

**时机**：侦察完成后、测试阶段之前执行。

1. **收集情报输入**：从 `recon_results.md` 和浏览器侦察中汇总以下信息：
   - 目标域名（如 `xsecagent.com`）
   - 组织/公司名称（如 `XSec Technology`）
   - 发现的邮箱地址（如 `admin@xsecagent.com`）
   - 发现的手机号
   - 发现的人名/用户名
   - 前端资源中发现的关键词、产品名、项目代号
   - JS/HTML 中泄露的任何内部信息

2. **运行脚本**：
   ```bash
   python3 scripts/social_engineering_dict.py \
     --target "<目标标识>" \
     --domain "<目标域名>" \
     --org "<组织名称>" \
     --recon-file <hostname>_<port>/recon_results.md \
     --names "姓名1" "姓名2" ... \
     --emails "admin@target.com" ... \
     --phones "13800138000" ... \
     --keywords "关键词1" "关键词2" ... \
     --output-dir <hostname>_<port>/social_dicts/
   ```
   - `--target`（必需）: 目标标识，可与域名或组织名相同。
   - `--domain`（强烈建议）: 驱动域名衍生词根，效果显著。
   - `--org`（强烈建议）: 组织名衍生词根及首字母缩写。
   - `--recon-file`（推荐）: 自动解析 `recon_results.md`，提取邮箱、手机号、关键词。
   - `--names`: 手动提供侦察中发现的人名。
   - `--emails`: 手动提供发现的邮箱。
   - `--phones`: 手动提供发现的手机号。
   - `--keywords`: 手动提供额外关键词（产品名、项目代号等）。

3. **生成策略**：脚本基于人类密码行为心理学，按以下层级生成：
   - **词根提取**: 域名拆分 → 组织名缩写 → 邮箱 local-part → 关键词
   - **密码生成（多层）**: 词根+数字后缀 → 词根+年份 → 词根+特殊符号 → Leet 替换 → 键盘行走 → 日期/手机号派生 → 中国特有情感数字
   - **组合字典**: 优先生成高命中率组合（用户名==密码、用户名+常见后缀、管理员×社工密码）

4. **输出文件**（保存至 `social_dicts/` 目录）：
   | 文件 | 内容 | 用途 |
   |------|------|------|
   | `social_usernames.txt` | 社工用户名字典 | 替代/补充通用用户名字典 |
   | `social_passwords.txt` | 社工密码字典 | 优先于通用密码字典使用 |
   | `social_combined.txt` | 用户名:密码 组合 | 用于高置信凭据抽样 |
   | `social_report.txt` | 生成报告 | 记录情报统计与生成分类 |


5. **心理学依据**（详见 `references/social_engineering_patterns.md`）：
   - 熟悉性启发：用户倾向于使用与工作场景相关的词汇
   - 认知懒惰：喜欢简单数字后缀（123、123456）
   - 情感锚定：中国用户常用 520、888、1314 等情感数字
   - 动作依赖：键盘行走模式依赖肌肉记忆
   - 边缘满足：系统要求特殊符号时只在末尾加 `!` 或 `@123`

### 阶段 3：测试阶段（逻辑验证 + 全量凭据审计）
**目标**：验证脚本逻辑，并对全量字典完成弱口令/密码喷洒审计。

1. **优先使用侦察阶段发现的敏感信息登录**：在生成审计脚本之前，先直接尝试侦察阶段在前端资源、注释或配置文件中发现的凭据。
   - 从 `recon_results.md` 的「敏感信息」章节提取所有疑似账号/密码。
   - 手动或用脚本逐一向登录接口发送请求，记录结果。
   - 若直接命中，立即记录至 `results.txt` 并停止本轮审计；若均失败，继续执行后续步骤。
2. **生成脚本**：基于 `scripts/example.py` 创建 `<target_folder>/brute_force.py`，填入所有目标特定配置。
3. **运行脚本逻辑测试**：`python brute_force.py --test`
   - **单线程**：严格使用 1 个线程，测试 3-5 组凭据。
   - **验证码策略验证**：若侦察结论为"可绕过"，测试中确认无验证码字段时请求正常被处理；若结论为"可复用"，确认同一验证码值第 2 次请求未报验证码错误；若为 OCR 模式，确认识别结果格式正确。
   - **验证**：确认加密输出正确、验证码已解决/绕过、成功/失败判断准确。
   - **修复问题**：若测试失败（如加密错误、验证码绕过失效），先调试修复再继续。
4. **用户名枚举差异确认**：
   - **前提**：仅在阶段1侦察结论确认「存在用户名枚举差异」时执行。
   - 默认只使用 2-5 个测试用户名、用户提供用户名或前端泄露用户名做差异确认。
   - 若确认可枚举，可使用 `assets/wordlists/usernames/16817条全部.txt`、手机号字典或其他大字典做全量枚举。
   - 将确认出的有效用户名候选保存至 `<target_folder>/valid_users.txt`，并标注来源和测试范围。
5. **全量凭据审计**：
   - 按价值排序选择凭据组合：用户提供和目标前端泄露优先，默认凭据其次，社工字典和通用字典最后；对选定字典做全量尝试，不做人为截断。
   - 默认 `max_threads=1`，按 `delay_seconds` 执行；可按目标响应能力提高并发以在有限时间内跑完全量。若服务器响应慢、出现验证码、429/503、锁定提示或风控信号，立即降速或停止。
   - 原始敏感内容保存到受控证据目录；共享发现、截图展示、报告和委派使用最少必要的原始摘录（xSec 不做自动脱敏）与证据引用，截断只因体积限制并明确标记。
   - 命中有效凭据后立即停止本轮审计，保存 browser state、issue、win 和报告证据。
6. **边界触发处理**：若因锁定/验证码/风控等边界条件无法继续，返回 `blocked` 或 `next_suggestions`，说明触发原因和已覆盖范围。

---

## 凭据审计策略与字典选择

> **核心原则**：先使用来源可信、数量小、命中价值高的凭据候选；再对社工字典和通用字典做全量尝试，保证在有限时间内跑完。

### 0. 来源优先级

默认优先级：

- **直接证据**：用户提供凭据、测试账号、目标前端泄露的测试账号或临时口令。
- **小样本默认凭据**：`admin/admin`、`admin/123456`、产品默认口令等。
- **社工字典**
- **通用字典**

---

根据阶段 1 的侦察结果选择后续策略：

### A. 用户名枚举策略（可枚举时）
- **差异确认**：默认只做 2-5 个测试用户名或明显测试用户名的响应差异确认。
- **扩大枚举**：确认可枚举后，使用 `assets/wordlists/usernames/16817条全部.txt`、手机号字典或其他大字典做全量枚举。

### B. 密码喷洒（存在锁定风险时）
- 若服务器在 3-5 次失败后锁定账号，**禁止对单个用户进行暴力破解**。
- 密码顺序由证据来源决定：产品默认口令、用户提供口令、前端泄露口令优先，通用字典全量使用。

### C. 组合爆破（无枚举、无锁定）

- 先跑高置信组合（用户名==密码、默认凭据、社工组合）并设置 `stop_on_first_valid_credential=true`；命中即停。
- 再扩展到 `TOP241用户名.txt`、`TOP603密码.txt`、`CN本土化password-2010条.txt`、`burp密码-3424条.txt` 或 `16817条全部.txt` 做全量组合，保证在有限时间内跑完。

字典选择参考：

| 目标类型 | 用户名字典 | 密码字典 |
|---|---|---|
| 国内后台管理系统 | `TOP241用户名.txt` | `CN本土化password-2010条.txt` |
| 国内手机号登录 | `特殊手机号.txt` | `CN本土化password-2010条.txt` |
| 国际/境外目标 | `TOP241用户名.txt` | `burp密码-3424条.txt` |
| 快速首轮测试 | `TOP241用户名.txt` | `TOP603密码.txt` |

---

## 脚本生成规范

为新目标生成 `brute_force.py` 时，遵循以下规则：
1. **基于模板**：以 `scripts/example.py` 为起点，不要从零编写。
2. **线程本地 Session**：使用 `threading.local()` 为每个线程维护独立的 `requests.Session`，保证 Cookie 隔离。
3. **加密实现**：精确实现侦察阶段发现的加密方式。RSA/AES 引入 `pycryptodome`，SM2/SM4 引入 `gmssl`。
4. **验证码处理**（按优先级，与侦察阶段结论保持一致）：
   - **参数删除绕过**：请求中不携带任何验证码字段，执行全量审计尝试。
   - **空值绕过**：固定传 `captcha=""`，执行全量审计尝试。
   - **Cookie 绕过**：不携带验证码相关 Cookie 发送请求。
   - **复用模式**：启动时获取一次验证码，全程复用；每 `CAPTCHA_REUSE_LIMIT`（默认 80）次请求后刷新一次（防服务端过期兜底）。
   - **OCR 模式（兜底）**：每次请求前调用 `solve_image_captcha()`，使用单例 `ddddocr.DdddOcr(show_ad=False)` 实例；服务端直接返回校验码时直接调接口提取。
5. **重试逻辑**：HTTP 429/503 时指数退避重试；验证码校验失败时重试。
6. **日志记录**：写入 `<target_folder>/brute.log`，测试模式下使用 `logging.DEBUG`。
7. **结果文件**：将发现的凭据以 `用户名:密码` 格式追加到 `<target_folder>/results.txt`。
8. **命令行参数**：始终包含 `--test`、`--threads`、`--users`、`--passwords`、`--delay` 参数。

---

## 参考文件
- `scripts/example.py` — 所有生成脚本的基础模板（同时也是通用凭据审计框架核心文件，见下方详细说明）。
- `assets/example_asset.txt` — 常见模式说明。
- `references/encryption_patterns.md` — JS 加密方法识别指南。
- `references/api_reference.md` — requests、pycryptodome、ddddocr API 快速参考。
- `references/social_engineering_patterns.md` — 社工字典密码行为心理学指南。
- `scripts/social_engineering_dict.py` — **社工字典生成器**。基于目标信息和心理学模式生成定制化账号密码字典。支持从侦察结果（JSON/Markdown）自动提取邮箱、手机号、关键词，生成三层字典：用户名、密码、组合字典。
- `scripts/example.py` — **通用凭据审计框架模板（核心文件）**。包含所有可能用到的方法，直接复制到目标文件夹、填写顶部 `[CONFIG]` 区域即可运行；其他模块按需修改，无需改动的部分保持原样。
  - `[CONFIG]` 目标配置区：URL、字段名、加密函数指针、验证码URL、成功/失败/重试标志、并发参数、字典路径
  - `[CRYPTO]` 加密工具箱：`rsa_encrypt` / `aes_cbc_encrypt` / `aes_ecb_encrypt` / `sm4_encrypt` / `md5` / `sha256` / `b64_encode` / `hex_encode`
  - `[CAPTCHA]` 验证码：
    - `probe_captcha_bypass()` — **优先执行**，依次测试参数删除/空值/Cookie删除绕过，返回绕过策略枚举 `BYPASS_NONE / BYPASS_OMIT_FIELD / BYPASS_EMPTY_VALUE / BYPASS_NO_COOKIE`
    - `probe_captcha_reuse()` — 获取一个验证码，连续提交 3 次，判断是否可复用，返回 `True/False` 及建议刷新间隔
    - `solve_image_captcha()` — ddddocr 单例OCR（仅在绕过和复用均不可用时调用）
    - `get_slider_code()` — 服务端直接返回校验码的绕过
  - `[HTTP]` HTTP工具：`get_session`（线程本地Session保持Cookie）/ `build_payload`（自动加密）/ `do_request`（指数退避重试）/ `is_success` / `is_user_exists`
  - `[PAYLOAD]` 载荷策略：`gen_spray_rounds`（密码喷洒）/ `gen_combined`（组合爆破）/ `gen_enumerate_users`（用户名枚举）
  - `[ENGINE]` `BruteForcer` 类：自适应并发调节 / tqdm进度条 / 结果写文件 / `run_test` 测试模式 / `run` 全量执行
  - `[MAIN]` 命令行：`--test` / `--threads` / `--users` / `--pwds` / `--delay` / `--spray` / `--enum`

## 技能触发条件
当用户提供 URL 并提出以下请求时，使用本技能：
- "弱口令"、"爆破"、"密码测试"、"登录破解"、"撞库"
- "brute force"、"login crack"、"password spray"、"automated login testing"
- "帮我测试这个登录页面"、"这个网站有没有弱口令"
- "生成社工字典"、"组社工字典"、"social engineering dictionary"
