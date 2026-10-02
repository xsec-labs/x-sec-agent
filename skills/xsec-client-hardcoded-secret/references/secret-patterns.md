# 敏感信息搜索正则速查 & 工具清单

## 正则模式速查表

可直接用于 `grep -rEn` 或 Burp Suite Search。

| 类型 | 正则模式 |
|------|---------|
| AWS Access Key | `AKIA[0-9A-Z]{16}` |
| AWS Secret Key | `(?i)aws.{0,20}['"][0-9a-zA-Z/+]{40}['"]` |
| 通用 API Key | `(?i)(api[_-]?key\|apikey)\s*[=:]\s*['"][A-Za-z0-9\-_]{16,}['"]` |
| 通用 Secret | `(?i)(secret\|app_secret\|appsecret)\s*[=:]\s*['"][^'"]{8,}['"]` |
| 通用 Token | `(?i)(token\|access_token\|auth_token)\s*[=:]\s*['"][A-Za-z0-9\-_.]{16,}['"]` |
| Bearer Token | `(?i)bearer\s+[A-Za-z0-9\-_.~+/]+=*` |
| JWT | `eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+` |
| 阿里云 AK/SK | `(LTAI\|AKID)[A-Za-z0-9]{16,}` |
| 腾讯云 SecretId | `AKIDz?[0-9a-zA-Z]{32,}` |
| 数据库密码字段 | `(?i)(db_pass\|database_password\|mysql_pwd)\s*[=:]\s*['"][^'"]{4,}['"]` |
| 私钥片段 | `-----BEGIN (RSA\|EC\|OPENSSH\|DSA) PRIVATE KEY-----` |
| 基础认证 URL | `https?://[^:]+:[^@]+@[^/\s]+` |
| 内网地址 | `(192\.168\.\d+\.\d+\|10\.\d+\.\d+\.\d+\|172\.(1[6-9]\|2\d\|3[01])\.\d+\.\d+)` |
| 内部高危端口 | `https?://[^"'\s]*(8080\|8443\|9090\|8888\|3000\|8000\|8001)[^"'\s]*` |
| 对称密钥（AES） | `(?i)(aes\|des\|key\|iv)\s*[=:]\s*['"][A-Fa-f0-9]{16,}['"]` |
| 硬编码密码 | `(?i)(password\|passwd\|pwd)\s*[=:]\s*['"][^'"]{6,}['"]` |
| 测试账号特征 | `(?i)(test\|admin\|debug)\s*(account\|user\|passwd\|password)\s*[=:]` |
| 钉钉/企微 Webhook | `https://oapi\.(dingtalk\|weixin)\.qq\.com/robot/send\?access_token=[A-Za-z0-9]+` |
| SMTP 凭据 | `(?i)(smtp_pass\|mail_password\|smtp_auth)\s*[=:]\s*['"][^'"]+['"]` |

---

## 批量扫描脚本（scan_secrets.sh）

```bash
#!/bin/bash
# 用法：./scan_secrets.sh <目录>
TARGET="${1:-.}"
PATTERNS=(
  'AKIA[0-9A-Z]{16}'
  '(?i)(api[_-]?key|apikey|secret|app_secret)\s*[=:]\s*["'"'"'][A-Za-z0-9\-_]{16,}["'"'"']'
  '(?i)(password|passwd|pwd)\s*[=:]\s*["'"'"'][^"'"'"']{6,}["'"'"']'
  '(?i)(token|access_token|auth_token)\s*[=:]\s*["'"'"'][A-Za-z0-9\-_.]{16,}["'"'"']'
  'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
  '-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----'
  '(192\.168\.|10\.\d+\.|172\.(1[6-9]|2\d|3[01])\.)\d+\.\d+'
  '(LTAI|AKID)[A-Za-z0-9]{16,}'
)

echo "=== 敏感信息扫描：$TARGET ===" | tee scan_results.txt
for pat in "${PATTERNS[@]}"; do
  echo "" | tee -a scan_results.txt
  echo "--- Pattern: $pat ---" | tee -a scan_results.txt
  grep -rEn "$pat" "$TARGET" \
    --include="*.js" --include="*.ts" --include="*.java" \
    --include="*.json" --include="*.yaml" --include="*.yml" \
    --include="*.xml" --include="*.plist" --include="*.config" \
    --include="*.env" --include="*.py" --include="*.go" \
    2>/dev/null | tee -a scan_results.txt
done
echo "扫描完成，结果已保存至 scan_results.txt"
```

---

## 工具清单

| 工具 | 用途 | 安装 |
|------|------|------|
| `apktool` | APK 解包（smali + 资源） | `brew install apktool` |
| `jadx` | APK 反编译为 Java | `brew install jadx` |
| `@electron/asar` | Electron asar 解包 | `npm i -g @electron/asar` |
| `sourcemapper` | Source Map 源码恢复 | `npm i -g sourcemapper` |
| `reverse-sourcemap` | Source Map 源码恢复（备选） | `npm i -g reverse-sourcemap` |
| `js-beautify` | JS 格式化美化 | `npm i -g js-beautify` |
| `strings` | 二进制字符串提取 | macOS 内置 |
| `p7zip` | 多格式解包（.exe/.nsis） | `brew install p7zip` |
| `ipatool` | IPA 下载（需 Apple ID） | `pip install ipatool` |
| `miniprogram-unpacker` | 微信小程序 wxapkg 解包 | `npm i -g miniprogram-unpacker` |
| `trufflehog` | Git 历史敏感信息扫描 | `pip install trufflehog` |
| `gitleaks` | 仓库/文件敏感信息扫描 | `brew install gitleaks` |
