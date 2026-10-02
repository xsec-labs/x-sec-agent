# 私钥验证方法（RSA / EC / SSH）

> 所有验证操作均在本地执行，禁止对真实业务密文、真实服务端或真实主机发起任何请求。

## 私钥类型识别

```bash
# 查看 PEM 文件头部，判断类型
head -1 leaked_key.pem
```

| 头部标识 | 类型 | 用途 |
|---------|------|------|
| `-----BEGIN RSA PRIVATE KEY-----` | RSA 传统格式（PKCS#1） | 加解密、签名、TLS |
| `-----BEGIN PRIVATE KEY-----` | PKCS#8（RSA/EC/Ed25519） | 加解密、签名 |
| `-----BEGIN EC PRIVATE KEY-----` | EC 裸格式 | ECDSA 签名、ECDH 密钥协商 |
| `-----BEGIN OPENSSH PRIVATE KEY-----` | OpenSSH 格式 | SSH 登录认证 |
| `-----BEGIN CERTIFICATE-----` | 证书（公钥，非私钥） | 不属于私钥泄露 |

## 禁止操作

| 禁止 | 原因 |
|------|------|
| `ssh -i key.pem user@<host>` 连接真实主机 | 接管真实服务器 |
| `openssl rsautl -decrypt` 解密真实业务密文 | 获取用户隐私数据 |
| 使用私钥伪造真实业务签名请求 | 绕过真实系统鉴权 |
| 将私钥上传到在线检测平台 | 再次泄露凭据 |

## 验证步骤

### RSA 私钥

```bash
# 1. 格式与一致性检查（不做任何网络操作）
openssl rsa -in leaked_key.pem -check -noout
# 成功输出：RSA key ok

# 2. 提取公钥指纹（用于与服务端公钥比对，不登录主机）
openssl rsa -in leaked_key.pem -pubout 2>/dev/null \
  | openssl pkey -pubin -noout -text \
  | grep -E "Public-Key|Key-Length|Exponent"

# 3. 本地签名能力测试（仅对本地临时文件，完成后立即删除）
echo "pentest-local-$(date +%s)" > /tmp/_pt_test.txt
openssl rsautl -sign -inkey leaked_key.pem \
  -in /tmp/_pt_test.txt -out /tmp/_pt_sig.bin 2>/dev/null \
  && echo "signing OK"
rm -f /tmp/_pt_test.txt /tmp/_pt_sig.bin
```

### EC 私钥

```bash
# 格式与有效性检查
openssl ec -in leaked_key.pem -check -noout
# 成功输出：EC Key valid

# 查看曲线类型
openssl ec -in leaked_key.pem -noout -text 2>/dev/null | grep "ASN1 OID"
```

### PKCS#8 格式（RSA/EC 通用）

```bash
# 有效性检查
openssl pkey -in leaked_key.pem -check -noout
# 成功输出：Key is valid
```

### OpenSSH 私钥（SSH）

```bash
# 1. 获取公钥指纹（不连接任何主机）
ssh-keygen -lf leaked_key.pem

# 2. 提取公钥内容（用于与目标 authorized_keys 比对）
ssh-keygen -yf leaked_key.pem
# 输出格式：ssh-rsa AAAA... 或 ecdsa-sha2-nistp256 AAAA...
```

> 获取公钥指纹后，由客户侧在目标主机 `~/.ssh/authorized_keys` 中比对，**测试人员不得直接发起 SSH 连接**。

## 结果解读

- `RSA key ok` / `EC Key valid` / `Key is valid` → 私钥格式完整，具备加解密或签名能力，属高危（若可被非预期主体获取）。
- SSH 公钥指纹若出现在客户服务器的 `authorized_keys` 中 → 可免密登录对应账号，属高危。
- 私钥有密码保护（提示 `Enter PEM pass phrase`）→ 降低即时利用风险，但密码强度和泄露途径需同步评估。
- 仅文件存在但解析报错（格式损坏、截断）→ 可记录为"疑似私钥材料"，影响降低但仍需整改。
