# 移动端实操：Android APK / iOS IPA / 小程序

## Android APK 分析

### 1. 获取 APK

```bash
# 方式一：从授权测试设备通过 ADB 提取
adb shell pm list packages | grep target_app
adb shell pm path com.target.app        # 获取 APK 路径
adb pull /data/app/com.target.app-1/base.apk /tmp/target.apk

# 方式二：apkeep 从公开渠道下载（需授权）
pip install apkeep
apkeep -a com.target.app /tmp/
```

### 2. 解包 APK（三选一）

```bash
# apktool：还原 smali 代码 + 资源文件
apktool d target.apk -o /tmp/apk_out/      # brew install apktool

# jadx：反编译为 Java 源码，可读性最佳（推荐）
jadx -d /tmp/apk_jadx/ target.apk          # brew install jadx

# unzip：直接查看 assets / dex / lib
mkdir /tmp/apk_raw && unzip target.apk -d /tmp/apk_raw/
```

### 3. 搜索敏感信息

```bash
# --- jadx 反编译目录 ---
cd /tmp/apk_jadx/

grep -rEin '(api[_-]?key|secret|password|token|ak|sk|appid|appkey)\s*=\s*"[^"]{8,}"' \
  --include="*.java"

grep -rEn '(192\.168\.|10\.\d+\.|http://[^"\s]*:(8080|8443|9090|3306|6379))' \
  --include="*.java"

# AES/DES 密钥初始化
grep -rEn '(SecretKeySpec|IvParameterSpec)\s*\(.*"[A-Za-z0-9+/=]{8,}"' \
  --include="*.java"

# --- 资源文件 ---
# strings.xml（常见硬编码位置）
grep -iE 'key|secret|token|password|url|endpoint|ak|sk' \
  /tmp/apk_out/res/values/strings.xml

# assets / res/raw 目录中的配置文件
find /tmp/apk_raw/assets/ /tmp/apk_raw/res/raw/ -type f | \
  xargs grep -lEi 'key|secret|token|password|endpoint' 2>/dev/null

# --- native .so 文件 ---
find /tmp/apk_raw/lib/ -name "*.so" | while read so; do
  echo "=== $so ==="
  strings "$so" | grep -iE \
    '(key|secret|token|password|ak|sk|http://|https://|192\.168\.)' | head -20
done
```

---

## iOS IPA 分析

### 1. 获取 IPA

```bash
# 方式一：ipatool（需 Apple ID 授权）
pip install ipatool
ipatool download -b com.target.app -o /tmp/target.ipa

# 方式二：从已授权越狱测试设备导出
ssh root@<device> "zip -r /tmp/app.ipa /var/containers/Bundle/Application/<UUID>/<App>.app"
scp root@<device>:/tmp/app.ipa /tmp/
```

### 2. 解包 IPA

```bash
mkdir /tmp/ipa_out
unzip target.ipa -d /tmp/ipa_out/
ls /tmp/ipa_out/Payload/*.app/
```

### 3. 搜索敏感信息

```bash
cd /tmp/ipa_out/Payload/

# plist 配置文件（批量转 xml 搜索）
find . -name "*.plist" | while read f; do
  plutil -convert xml1 -o /tmp/_tmp.plist "$f" 2>/dev/null && \
  grep -iE '(key|secret|token|password|ak|sk|http)' /tmp/_tmp.plist | \
  sed "s|^|$f: |"
done

# Mach-O 二进制 strings 提取
APP=$(ls *.app/ | head -1 | sed 's|/$||')
strings "$APP.app/$APP" | grep -iE \
  '(api[_-]?key|secret|password|token|bearer|ak|sk|accesskey)' | head -50

# Hybrid 应用内嵌 JS/HTML
find . \( -name "*.js" -o -name "*.html" \) | \
  xargs grep -EniH '(api[_-]?key|secret|password|token)\s*[=:]\s*["'"'"'][^"'"'"']{8,}'

# 配置 JSON / YAML
find . \( -name "*.json" -o -name "*.yaml" -o -name "*.yml" \) | \
  xargs grep -EniH '(key|secret|token|password|endpoint|ak|sk)'
```

---

## 小程序包分析（微信 / 支付宝）

### 获取与解包

```bash
# 从授权 rooted Android 设备提取微信小程序缓存包
# 路径：/data/data/com.tencent.mm/MicroMsg/<hash>/appbrand/pkg/
adb pull /data/data/com.tencent.mm/MicroMsg/<hash>/appbrand/pkg/ /tmp/wxapkg/

# 解包（需 Node.js）
npm install -g miniprogram-unpacker
miniprogram-unpacker /tmp/wxapkg/xxx.wxapkg /tmp/miniapp_out/
```

### 搜索敏感信息

```bash
cd /tmp/miniapp_out/
grep -rEin \
  '(appId|appSecret|apiKey|token|secret|key)\s*[=:]\s*["'"'"'][A-Za-z0-9]{8,}' \
  --include="*.js" --include="*.json"

# 提取接口地址
grep -rEo 'https?://[^\s"'"'"'>]+' --include="*.js" | sort -u
```
