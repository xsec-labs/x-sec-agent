---
name: xsec-jwt-security
description: JWT 安全整体测试方法论。只要用户登录成功、截获了 JWT、或在请求/响应中发现 JWT 令牌，就应立即触发本 skill。全面涵盖四大测试方向：① JWT 密钥爆破（hashcat HS256/HS384/HS512 + 内置字典）；② 签名伪造与校验绕过（alg:none、空签名、算法混淆、签发逻辑滥用）；③ 有效期控制缺陷（缺失 exp、过长有效期、撤销失效）；④ 刷新令牌无限续期。用户提到 JWT、Bearer token、token 爆破、弱密钥、想伪造或修改 JWT、jsonwebtoken、登录后拿到 token，均应使用本 skill。
---

# JWT 安全整体测试方法论

## 编排适配

- 适用场景：登录成功、请求/响应/Cookie/LocalStorage 中发现 JWT 或 Bearer Token，需要测试算法、签名校验、弱密钥、有效期与撤销。
- 触发信号：`jwt_token_detected`、`bearer_token_detected`、`authenticated_session_obtained`、`authorization_header_observed`、`storage_token_detected`。
- 测试前置环境：必须有完整 JWT 和低影响受保护接口；HMAC 弱密钥测试需要 hashcat/john 或等价工具，伪造验证必须限定测试账号和只读接口。
- 必需工件：`token_sample`、`request_corpus`、`browser_state`、`protected_endpoint_baseline`、`jwt_wordlists`。
- 解锁输出：`jwt_weak_secret_detected`、`token_forgery_candidate`、`session_token_invalidation_candidate`、`access_control_review_needed`、`browser_storage_review_needed`。
- 阻断条件：无 JWT、令牌不完整/已过期且无法刷新、scope 禁止令牌重放或缺少安全的验证接口。

## 测试全景

拿到 JWT 后按以下顺序推进，每个阶段视情况决定是否深入：

```
阶段一：解析 JWT 结构与识别算法
    ↓
阶段二：密钥爆破（HMAC 算法时）
    ↓（若爆破成功 → 进入签名伪造；否则继续）
阶段三：签名校验绕过与伪造测试
    ↓
阶段四：有效期控制与撤销机制测试
```

不同阶段可并行推进，但爆破密钥后的伪造测试必须在爆破成功的前提下进行。

---

## 阶段一：JWT 解析与识别

**目标**：在不修改任何内容的前提下，摸清 JWT 的基本结构和使用方式。

1. **提取 JWT**：从登录响应、Authorization 头、Cookie、LocalStorage、抓包记录中定位令牌。
2. **Base64 解码 Header 和 Payload**（不需要密钥），观察以下字段：
   - Header：`alg`（算法类型）、`typ`、`kid`（密钥 ID）
   - Payload：`sub`、`uid`、`role`、`exp`、`iat`、`nbf`、`jti`、`iss`、`aud`
3. **确认算法类型**，决定后续路径：
   - `HS256 / HS384 / HS512`：使用共享密钥，**可进行爆破**，优先进入阶段二
   - `RS256 / ES256` 等非对称算法：不可爆破私钥，直接进入阶段三的算法混淆测试
   - `none`：本身就是危险信号，直接进入阶段三
4. **记录验证点**：选择一个低影响、只读、可重复调用的受保护接口，作为后续所有阶段的统一验证基线。

---

## 阶段二：JWT 密钥爆破（HMAC 算法）

**适用条件**：Header 中 `alg` 为 `HS256`、`HS384` 或 `HS512`。

### 工具与字典

- 工具：`hashcat`（推荐，GPU 加速）或 `john`
- 内置字典（位于本 skill 的 `wordlists/` 目录下）：
  | 文件 | 条数 | 说明 |
  |------|------|------|
  | `jwt-secrets.txt` | ~250 | 常见弱密钥、框架默认值、占位符 |
  | `seclists-jwt-secrets.txt` | ~104,000 | SecLists 收录的真实泄露 JWT 密钥 |
  | `rockyou.txt` | ~14,344,000 | 经典通用密码字典，覆盖面最广 |
- 推荐爆破顺序：先用 `jwt-secrets.txt` 和 `seclists-jwt-secrets.txt`（速度快），未命中再追加 `rockyou.txt`
- `rockyou.txt` 为大型本地字典，不纳入 Git；使用前执行 `scripts/ensure_rockyou.sh`，若本地缺失会自动从 SecLists 下载并解压。

### hashcat 爆破步骤

**Step 1：准备 JWT**

将完整 JWT 保存到文件（注意保持原始格式，三段 Base64 用 `.` 分隔）：
```bash
echo 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.XXXXX' > /tmp/jwt.txt
```

**Step 2：运行 hashcat**

```bash
SKILL_DIR="/path/to/skills/xsec-jwt-security"

# 第一轮：JWT 专用字典（快，几秒内出结果）
hashcat -a 0 -m 16500 /tmp/jwt.txt \
  "$SKILL_DIR/wordlists/jwt-secrets.txt" \
  "$SKILL_DIR/wordlists/seclists-jwt-secrets.txt"

# 确保 rockyou 大字典存在；本地已有则跳过，缺失则自动下载
bash "$SKILL_DIR/scripts/ensure_rockyou.sh"

# 第二轮：rockyou 大字典（~1400 万条，覆盖更广）
hashcat -a 0 -m 16500 /tmp/jwt.txt \
  "$SKILL_DIR/wordlists/rockyou.txt"

# GPU 不可用时强制 CPU 模式（任意轮次追加 --force）
hashcat -a 0 -m 16500 /tmp/jwt.txt \
  "$SKILL_DIR/wordlists/seclists-jwt-secrets.txt" --force

# 查看已破解结果
hashcat -a 0 -m 16500 /tmp/jwt.txt \
  "$SKILL_DIR/wordlists/rockyou.txt" --show
```

> HS384 和 HS512 同样使用 `-m 16500`，hashcat 会自动根据 JWT Header 识别变体。

**Step 3：判断结果**

- **爆破成功**：hashcat 输出 `<jwt>:<secret>`，记录密钥，进入下面的签名伪造部分。
- **爆破失败**：内置字典未命中，记录"未发现弱密钥"，继续进行阶段三的其他测试。

### 爆破成功后：验证密钥并构造伪造令牌

```python
import jwt  # pip install PyJWT

secret = "找到的密钥"
original_token = "原始 JWT"

# 验证解码
payload = jwt.decode(original_token, secret, algorithms=["HS256"])
print(payload)  # 确认密钥正确

# 构造最小化测试 payload（只改一个字段做对照）
test_payload = dict(payload)
test_payload["role"] = "admin"  # 示例：仅修改角色字段

forged_token = jwt.encode(test_payload, secret, algorithm="HS256")
print(forged_token)
```

将伪造令牌发送到阶段一确认的验证接口，观察服务端是否接受并信任修改后的声明字段。

---

## 阶段三：签名校验绕过与伪造测试

**目标**：验证服务端是否在没有正确密钥的情况下仍错误接受令牌，或存在签发逻辑可被滥用。

### 3.1 alg:none 测试

将 Header 中 `alg` 改为 `none`，移除签名部分（保留末尾 `.`），观察服务端是否接受：

```bash
python3 -c "
import base64, json

header = base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).rstrip(b'=').decode()
payload = base64.urlsafe_b64encode(json.dumps({'sub':'1234','role':'admin'}).encode()).rstrip(b'=').decode()
print(f'{header}.{payload}.')
"
```

### 3.2 空签名测试

保持 Header 中 `alg` 不变，将签名部分替换为空字符串或固定占位符，发送给服务端。若返回成功，说明签名未被验证。

### 3.3 算法混淆（RS256 → HS256）

仅适用于服务端使用 RS256（非对称）但可能接受 HS256 的情况：
- 获取服务端公钥（常见路径：`/.well-known/jwks.json`、`/api/auth/keys`）
- 将 Header 中 `alg` 改为 `HS256`，用公钥内容作为 HMAC 密钥重新签名
- 若服务端接受，说明算法校验不严格

### 3.4 签发逻辑测试

检查令牌签发接口是否真正绑定服务端身份校验：
- 身份参数是否可被客户端直接控制（如 `?user_id=xxx`、请求体中的 `role` 字段）
- 未登录或低权限状态下能否直接调用签发接口获得任意身份令牌

### 对照组原则

每次测试只改变一个变量：
- 对照组 A：合法基线令牌 → 验证接口应成功
- 对照组 B：修改后异常令牌 → 观察服务端是否拒绝或仍接受

仅当"服务端接受异常令牌并返回对应业务结果"时，才足以确认问题存在。

---

## 阶段四：有效期控制与撤销机制测试

**目标**：验证令牌是否具备有效的生命周期控制，以及撤销机制是否真正落在服务端。

### 4.1 缺失 exp 或有效期过长

- 解码 Payload，确认是否包含 `exp` 字段
- 若有 `exp`，计算有效期时长，判断是否远超业务合理范围（如访问令牌超过 24 小时）
- 记录为候选问题，需结合服务端验证确认

### 4.2 超时后仍可用（时间维度验证）

- 等待合理时间后，用同一旧令牌访问验证接口
- 若服务端仍返回成功，确认过期校验未生效

### 4.3 登出后仍可用（状态维度验证）

- 执行登出操作，保留登出前的令牌
- 用旧令牌重新访问验证接口，若仍成功则撤销机制失效
- 同样测试：密码修改后、角色调整后、账户禁用后旧令牌是否失效

### 4.4 刷新令牌无限续期

- 多次调用刷新接口，观察旧刷新令牌是否被自动作废（滚动失效）
- 若旧刷新令牌仍可继续换取新访问令牌，说明存在无限续期链路

---

## 关键判断点

- `iat` 只是签发时间，不能替代 `exp`。
- `exp` 存在不等于安全——有效期过长、服务端不校验、无限刷新都是有效期缺陷。
- 前端倒计时、本地 Token 删除不能证明服务端过期校验已生效。
- 只有服务端响应体现了身份/数据/权限变化，才是签名伪造漏洞的真正证据；单纯 200 状态码不够。
- `alg:none` 被接受、签名清空仍可用，说明服务端可能完全不校验签名。
- 爆破出密钥但无法通过伪造令牌影响服务端行为，仍应记录为弱密钥问题（规范类），区别于可利用漏洞。

---

## 证据链要求

每个发现至少保留：
1. **基线证据**：合法令牌 + 验证接口成功响应，证明测试路径本身有效
2. **异常证据**：异常令牌 + 服务端仍接受的响应，说明变化了什么、服务端如何响应
3. **差异对比**：两次请求的关键字段对比（令牌结构差异、响应内容差异、时间差/状态变化）

证据全部脱敏：不保留完整 Token 原文、不保留真实 IP/域名、不保留真实账号标识。

---

## 风险定级思路

| 场景 | 参考等级 |
|------|---------|
| 爆破出弱密钥，可伪造任意身份令牌，影响高权限接口 | 高危 |
| alg:none 或签名绕过，可冒用他人身份或提权 | 高危 |
| 签发接口可为任意身份生成可用 JWT | 高危 |
| 访问令牌有效期极长（如 30 天以上），且登出后仍可用 | 中危 |
| exp 缺失或过长，但权限低且无撤销场景证据 | 低~中危 |
| 仅发现弱密钥，但无法证明可利用影响 | 低危（规范问题） |
| 仅发现 exp 字段缺失，无法复现旧令牌持续可用 | 待确认 |

---

## 修复建议

- **密钥**：使用高熵随机密钥（≥256 位），禁止使用默认值、空字符串或常见词语
- **算法**：显式限制可接受算法，拒绝 `none`、空签名及算法降级请求
- **有效期**：访问令牌建议 15 分钟～2 小时，刷新令牌设置上限并支持滚动失效
- **撤销**：登出、密码修改、角色调整、账户禁用时主动失效旧令牌（黑名单或版本号机制）
- **签发**：令牌签发必须绑定服务端已认证的身份，不接受客户端自定义目标身份参数

## 复测步骤

1. 重新运行 hashcat，确认弱密钥已被替换，爆破无结果
2. 发送 alg:none 及空签名请求，确认服务端返回 401/403
3. 登出后用旧令牌访问，确认被拒绝
4. 等待 exp 到期后访问，确认被拒绝
5. 抽样复测多个接口（网关、业务接口、管理接口），确认修复一致性

---

## 报告模板

### JWT 弱密钥（爆破成功）

```
漏洞名称：JWT 弱签名密钥
漏洞概述：系统 JWT 使用 HMAC 算法签名，经字典爆破发现签名密钥为弱密钥，
          攻击者可据此伪造任意身份的合法令牌。
验证方式：使用 hashcat 对截获的 JWT 进行字典攻击，成功恢复签名密钥；
          使用恢复密钥重新签名的伪造令牌在服务端验证通过。
影响评估：持有任意合法 JWT 的人员可伪造高权限或其他用户身份令牌，
          风险范围取决于可访问接口的权限覆盖面。
修复建议：立即更换高熵随机密钥并使所有现存令牌失效。
```

### JWT 签名校验绕过

```
漏洞名称：JWT 签名校验缺失 / 绕过
漏洞概述：服务端未严格校验 JWT 签名，接受了 <alg:none / 空签名 / 算法混淆> 的令牌，
          并据此信任其中的身份或权限声明。
验证方式：构造最小化对照令牌（仅修改算法/签名），服务端返回与声明一致的业务结果。
影响评估：攻击者无需密钥即可伪造任意身份令牌，可能导致身份冒用、横向访问或权限提升。
修复建议：显式限制可接受算法，服务端强制校验签名完整性。
```

### JWT 有效期控制缺陷

```
漏洞名称：JWT 有效期控制缺陷
漏洞概述：系统 JWT <缺失 exp / 有效期过长 / 登出后仍可用 / 刷新链路无限续期>，
          旧令牌在 <时间条件或状态变化> 后仍被服务端接受。
验证方式：在 <操作描述> 后，使用同一旧令牌访问验证接口，服务端返回成功响应。
影响评估：令牌一旦泄露，攻击者可在较长时间内持续复用，维持未授权访问能力。
修复建议：为访问令牌设置合理有效期，在服务端强制校验，并在敏感操作后主动撤销旧令牌。
```
