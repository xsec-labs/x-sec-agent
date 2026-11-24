---
name: xsec-browser-sensitive-storage
description: 针对浏览器端敏感信息存储的渗透测试方法论。**登录成功后应立即使用本 skill**，在前端界面中主动提取并检查所有存储区域是否以明文或弱编码方式保存了敏感信息。用户需要分析、验证、复测或撰写 Cookie、本地存储、sessionStorage、IndexedDB、前端缓存、记住密码、自动登录、明文凭据、可解码令牌、前端持久化配置 等相关问题时，应使用本 skill。只要存在"登录"动作、"记住密码"、"自动登录"、或前端单页应用，就应主动触发本 skill 进行检查。
---

# 浏览器端敏感信息存储测试方法论

## 编排适配

先读 [运行边界与证据口径](../../references/security-boundaries.md)。在分配的节点、预算和低影响约束内执行；`scope_policy` 只做资产归因，新发现的目标记录来源即可，不因 `in_scope=false` 停止；证据保留观察到的原始值，报告与委派只取证明问题所需的最小片段。

- 适用场景：登录成功后检查 Cookie、LocalStorage、SessionStorage、IndexedDB、缓存和记住登录功能是否保存敏感信息。
- 触发信号：`authenticated_session_obtained`、`remember_me_detected`、`browser_storage_token_detected`、`jwt_token_detected`、`password_value_in_storage_detected`。
- 测试前置环境：通常需要有可用浏览器上下文和登录态；需要能读取目标 origin 的浏览器存储快照。
- 参考工件：`browser_state`、`storage_snapshot`、`request_corpus`、`cookie_snapshot`。
- 解锁输出：`jwt_token_detected`、`session_token_invalidation_candidate`、`password_storage_candidate`、`insecure_crypto_candidate`、`cookie_security_review_needed`。
- 建议阻断（可低影响补齐时先补证再测）：无登录态、无浏览器上下文、目标未使用客户端存储。

## 触发时机

**登录成功后立即执行本 skill。** 不要等到发现可疑现象再检查——应在完成登录动作的同一步骤中主动扫描所有存储区域。以下任一条件满足即应触发：

- 刚完成授目标系统的登录操作（含账密登录、手机验证码、SSO、扫码登录）
- 用户提及"记住密码""自动登录""免登录""Token 保存"等功能
- 正在测试单页应用（Vue/React/Angular）或前后端分离系统
- 正在进行复测，需要验证修复后敏感信息是否彻底清除

## 适用场景

- 适用于 Web 应用、单页应用、前后端分离系统，以及带浏览器内核的前端壳应用。
- 适用于怀疑敏感信息被写入 `Cookie`、`localStorage`、`sessionStorage`、`IndexedDB`、`Cache Storage` 或前端持久化缓存的场景。
- 适用于存在“记住密码”“自动登录”“保存账号”“最近登录用户”“离线缓存”等功能的登录或业务入口。
- 适用于发现前端状态字段、令牌载荷、用户标识、账号口令、接口配置、业务对象标识被长期保存在终端侧的场景。
- 不适用于单纯服务端会话管理缺陷本身；若只是标准会话 ID 且无额外敏感语义，应先排除误报。

## 测试思想

- 这类问题的核心不在“前端有没有存值”，而在“前端是否保存了不该由终端长期掌握的敏感语义”。
- 优先区分三类对象：
  - 认证凭据：账号、密码、可直接复用的令牌、长期有效票据、接口密钥。
  - 高敏感身份数据：证件类标识、手机号、完整个人资料、可唯一识别用户的字段组合。
  - 高价值业务配置：后端连接信息、接口地址映射、权限标识、可辅助横向利用的元数据。
- 判断时不要把“随机会话标识”直接等同于漏洞。真正需要关注的是：
  - 值是否明文可读、弱编码可逆、结构化可解析。
  - 值是否超出浏览器端完成当前功能所必需的最小范围。
  - 值是否在退出登录、关闭浏览器、切换账号后仍持续存在。
  - 值是否可被同机普通用户、浏览器插件、脚本上下文或低门槛方式读取。
- 采用对照组思路，而不是只看一个截图下结论。必须回答“是什么操作导致写入”“不勾选相关功能时是否仍写入”“删除后是否影响功能”“退出后是否清理”。

## 参考方法（目标与常见路径，不是必须顺序）

下面是达成测试目标的常见路径，不是必须照做的脚本：可以合并步骤、调整顺序、跳过已经确认过的部分，或者换成你判断更合适的方法，只要仍能支撑下面的判断点和证据要求。

### 第一步：登录前建立基线（1~2分钟）

在干净浏览器环境（无历史缓存）中，登录前先用以下脚本记录各存储区域的初始状态：

```javascript
// 在浏览器控制台执行，记录登录前基线
(function() {
  console.log('=== 登录前存储基线 ===');
  console.log('[Cookie]', document.cookie || '（空）');
  console.log('[localStorage 键数]', localStorage.length);
  for (let i = 0; i < localStorage.length; i++) {
    const k = localStorage.key(i);
    console.log('  localStorage:', k, '=', localStorage.getItem(k));
  }
  console.log('[sessionStorage 键数]', sessionStorage.length);
  for (let i = 0; i < sessionStorage.length; i++) {
    const k = sessionStorage.key(i);
    console.log('  sessionStorage:', k, '=', sessionStorage.getItem(k));
  }
})();
```

截图或复制控制台输出，用于后续对比。如系统支持"记住密码"功能，准备两条路径分别测试：勾选 vs 不勾选。

### 第二步：登录成功后立即全量提取（核心步骤）

登录完成后，**立即**在浏览器控制台执行以下脚本，提取所有存储区域内容并进行敏感性预判：

```javascript
// 登录后全量存储扫描脚本
(async function scanStorage() {
  // 敏感键名正则：匹配常见认证、身份、账号相关词
  const SENSITIVE_KEYS = /pass|pwd|secret|token|auth|key|credential|user|account|phone|mobile|id_?card|身份|证件|手机|密码|账号|用户|姓名|name|email|session|login|remember/i;
  // 敏感值特征：Base64长字符串、JWT(eyJ开头)、11位手机号、32位以上hash
  const SENSITIVE_VALS = /^[A-Za-z0-9+/]{20,}={0,2}$|eyJ|^\d{11}$|[a-z0-9]{32,}/i;

  const results = { cookie: [], localStorage: [], sessionStorage: [], suspicious: [] };

  // 1. 扫描 Cookie
  document.cookie.split(';').forEach(c => {
    const [k, ...vArr] = c.trim().split('=');
    const v = vArr.join('=');
    const entry = { key: k, value: v };
    results.cookie.push(entry);
    if (SENSITIVE_KEYS.test(k) || SENSITIVE_VALS.test(v)) {
      results.suspicious.push({ type: 'Cookie', ...entry });
    }
  });

  // 2. 扫描 localStorage
  for (let i = 0; i < localStorage.length; i++) {
    const k = localStorage.key(i);
    const v = localStorage.getItem(k);
    const entry = { key: k, value: v };
    results.localStorage.push(entry);
    if (SENSITIVE_KEYS.test(k) || SENSITIVE_VALS.test(v)) {
      results.suspicious.push({ type: 'localStorage', ...entry });
    }
  }

  // 3. 扫描 sessionStorage
  for (let i = 0; i < sessionStorage.length; i++) {
    const k = sessionStorage.key(i);
    const v = sessionStorage.getItem(k);
    const entry = { key: k, value: v };
    results.sessionStorage.push(entry);
    if (SENSITIVE_KEYS.test(k) || SENSITIVE_VALS.test(v)) {
      results.suspicious.push({ type: 'sessionStorage', ...entry });
    }
  }

  // 4. 扫描 IndexedDB（列举数据库名）
  const dbList = await indexedDB.databases();
  if (dbList.length) {
    results.indexedDB = dbList.map(d => d.name);
    console.warn('[IndexedDB] 发现数据库:', results.indexedDB);
  }

  console.log('=== 全量扫描结果 ===');
  console.log('[Cookie]', results.cookie);
  console.log('[localStorage]', results.localStorage);
  console.log('[sessionStorage]', results.sessionStorage);
  console.warn('==== 疑似敏感条目 ====', results.suspicious);
  return results;
})();
```

重点关注控制台输出的 `suspicious` 数组，这些是需要逐一人工判断的候选项。

### 第三步：对可疑值进行编码识别与解码

对步骤二中标记的可疑值，依次用以下方法尝试解码，确认其语义。目的是判断字段**类别**，不需要展示完整内容：

**JWT 识别与解码**（格式为 `eyXxx.eyXxx.xxx`）：
```javascript
// 解码 JWT payload（非破坏性，不验签）
function decodeJWT(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
    return payload;
  } catch (e) { return null; }
}
// 使用示例：decodeJWT('eyJhbGci...')
```

**Base64 解码**：
```javascript
function tryDecodeBase64(val) {
  try { return atob(val); } catch(e) { return '无法解码'; }
}
```

**URL 解码**：
```javascript
decodeURIComponent('your%2Fencoded%3Dvalue')
```

解码后重点检查是否出现：账号名、手机号、身份证号、明文密码、权限字段（`role`/`admin`/`perm`）、有效期极长的时间戳、后端接口地址。

### 第四步：Cookie 安全属性核查

对每个含敏感语义的 Cookie，在 DevTools → Application → Cookies 面板核查安全属性（`HttpOnly` 的 Cookie 不会出现在控制台，必须在面板查看）：

| 属性 | 期望值 | 备注 |
|------|--------|------|
| `HttpOnly` | 已设置 | 防止 JS 读取，但不能弥补内容本身敏感的问题 |
| `Secure` | 已设置 | 仅 HTTPS 传输 |
| `SameSite` | `Strict` 或 `Lax` | 防 CSRF |
| `Expires/Max-Age` | 合理短期 | 敏感凭据不应永久存活 |

**重要**：安全属性不能弥补 Cookie 内容本身是账号密码或可复用凭据的问题，两者需独立判断。

### 第五步：构造对照组验证

- **登录前后对比**：将步骤一（基线）与步骤二（登录后）的输出做差集，确认哪些键由登录动作新增。
- **记住密码 vs 不勾选**：分别用两个隐私窗口执行登录，对比 `localStorage` / `Cookie` 差异。
- **退出登录后检查**：退出后重新运行扫描脚本，验证敏感键是否被清除。
- **刷新 / 重开浏览器后检查**：确认 `localStorage` / 持久 `Cookie` 是否在会话结束后仍残留。

### 第六步：IndexedDB 深入提取（如发现数据库）

```javascript
// 读取指定 IndexedDB 数据库中所有对象存储的全部记录
function dumpIndexedDB(dbName) {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(dbName);
    req.onsuccess = e => {
      const db = e.target.result;
      const storeNames = Array.from(db.objectStoreNames);
      const results = {};
      let pending = storeNames.length;
      storeNames.forEach(storeName => {
        const tx = db.transaction(storeName, 'readonly');
        const getAllReq = tx.objectStore(storeName).getAll();
        getAllReq.onsuccess = () => {
          results[storeName] = getAllReq.result;
          if (--pending === 0) resolve(results);
        };
      });
      if (!pending) resolve(results);
    };
    req.onerror = reject;
  });
}
// 使用：dumpIndexedDB('数据库名').then(r => console.log(JSON.stringify(r, null, 2)))
```

### 第七步：留证与报告整理

固定以下证据（值保留原文；仅在体积受限时截断并注明）：

1. 步骤一的基线截图（登录前各存储区域状态）
2. 步骤二的疑似敏感条目截图（登录后新增条目）
3. 解码后的完整原始字段内容和字段类型说明
4. 退出后的清理状态截图（是否仍存在敏感键）
5. 对照组截图（不同路径、不同账号的差异对比）

### 第八步：修复复测

修复后重新在干净环境使用步骤二的扫描脚本验证：

- 原先可疑键是否不再出现，或已替换为无业务语义的短期标识。
- 退出登录、刷新、关闭重开后，不会再次写入同类敏感信息。
- "记住密码"路径和"不记住"路径都已修复，避免只修一条逻辑分支。


## 关键判断点

- `Cookie` 中如果保存的是账号、密码、证件类标识、完整用户资料、可直接复用令牌，通常可判定为真实问题。
- `localStorage`、`sessionStorage`、`IndexedDB`、`Cache Storage` 中如果落盘的是明文口令、接口密钥、连接信息、权限数据或完整身份对象，通常比单纯 Cookie 属性缺失更严重。
- 仅有随机会话 ID 时，需继续判断其是否具备以下特征：
  - 退出后仍长期有效。
  - 可跨设备或跨账号直接复用。
  - 自身包含大量明文身份或权限语义。
- Base64、URL 编码、十六进制、简单拼接不构成有效保护；“不是明文显示”不代表风险消失。
- “为了记住密码而保存密码”不是合理豁免。应保存服务端受控的短期票据，而不是用户原始凭据。
- 不要把前端缓存中的普通 UI 状态、分页条件、主题配置误判为敏感信息；判断标准是其泄露后是否会导致认证、身份、隐私或高价值业务信息暴露。

## 证据链要求

- 证据应覆盖五个要素：触发入口、存储位置、敏感内容类型、可读性、持久性。
- 至少保留以下内容：
  - 触发动作说明，例如登录、勾选记住密码、刷新、退出后重开。
  - 存储介质截图，例如某个 `Cookie` 或某个本地存储键。
  - 原始键名和完整值，能够直接确认其语义属于账号、密码、身份标识、令牌或配置。
  - 前后对照证据，证明该值由特定操作写入。
  - 持久化证据，证明刷新、重开或退出后是否仍存在。
- 若需说明“可解码”，保留完整原始密文和完整解码结果，便于后续 Agent 复核与复用。
- 若需说明“可复用风险”，以方法论语言表述其可能性，不提供针对真实目标的扩展利用细节。

## 风险定级思路

- 高危：
  - 明文或可逆方式保存账号密码、长期有效令牌、接口密钥、后端连接凭据。
  - 保存的信息一旦泄露，可直接导致账号接管、身份冒用、接口重放或进一步进入其他系统。
- 中危：
  - 保存高敏感个人信息或业务敏感标识，虽未直接等同登录凭据，但可明显放大隐私泄露或社工风险。
  - 保存结构化认证数据，虽不能立即证明直接接管，但已超出前端最小保存原则。
- 低危：
  - 保存的是敏感度较低但仍不宜长期驻留前端的信息，且缺少直接利用链。
  - 或仅存在存储范围、生命周期控制不当，尚未发现高价值内容。
- 降级条件：
  - 数据仅为服务端随机会话标识，无法从前端证明其含有敏感语义，且生命周期、绑定关系、退出清理都符合预期。
- 升级条件：
  - 同类敏感值出现在多个存储位置。
  - 退出登录后仍存在。
  - 不同角色、不同账号都能稳定复现。
  - 值可被轻易解码为账号、密码、身份或权限字段。

## 修复与复测

- 修复方向
  - 不在浏览器端保存原始密码、长期凭据、接口密钥、后端连接信息。
  - 以服务端会话或受控短期票据替代前端持久化敏感数据。
  - 对必须存在于前端的字段做最小化设计，只保留完成功能必需的最少信息。
  - 严格控制生命周期：登录建立、退出清理、超时失效、切换账号清空。
  - 对 `Cookie` 补充 `HttpOnly`、`Secure`、`SameSite` 等属性，但不要把它们当作存储敏感内容的替代补救。
- 复测步骤
  - 清理浏览器站点数据后重新执行原始测试路径。
  - 检查原可疑键是否彻底消失，或是否被替换为无业务语义的短期标识。
  - 验证未勾选和勾选相关功能两条路径，避免只修一条逻辑分支。
  - 验证退出登录、切换账号、浏览器重启、会话超时后的清理行为。
  - 验证同域其他页面和子应用，避免遗留旧键或旁路逻辑。

## 报告表达模板

- 漏洞标题
  - 浏览器端敏感信息存储
- 漏洞描述
  - 在测试过程中，发现应用在浏览器端持久化存储了不应由客户端长期保存的敏感信息。相关数据出现在 `<storage-type>` 中，由 `<action>` 触发写入，退出或重启后仍可读取。经原文核验，存储内容包含 `<sensitive-category>`，超出前端完成当前功能所需的最小范围。
- 风险说明
  - 一旦终端被本地读取、恶意脚本访问或浏览器环境受控，攻击者可能获取上述敏感信息，进而导致 `<impact-summary>`。若存储内容属于账号凭据或可复用认证数据，风险可进一步扩大为账号接管或接口滥用。
- 证据概述
  - 1. 在干净环境下完成 `<action>` 后，浏览器端新增 `<key-name>`。
  - 2. 该原始键值可见 `<sensitive-category>` 特征。
  - 3. 在 `<refresh-or-relogin-condition>` 后该值仍存在，证明其具有持久化特征。
  - 4. 对照未开启相关功能或未登录状态，不存在相同敏感写入。
- 修复建议
  - 建议停止在浏览器端存储敏感信息，改为服务端维护会话或下发最小化、短期、受控的标识；同时完善退出清理、超时失效和同域统一清除逻辑，并复核所有相关前端存储点。
