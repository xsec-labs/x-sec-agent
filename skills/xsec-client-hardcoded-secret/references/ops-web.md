# Web 前端实操：Source Map + JS Bundle 分析

## Source Map 泄露分析

Source map（`.map` 文件）将混淆后的 JS 还原为可读源码，一旦在生产环境可访问，可完整恢复前端业务逻辑。

### 1. 发现 Source Map

```bash
# 在 JS 文件末尾查找 sourceMappingURL 注释
curl -s https://target.com/static/app.min.js | tail -5

# 批量探测常见路径
for f in app main chunk vendor; do
  for ext in js.map min.js.map bundle.js.map; do
    curl -s -o /dev/null -w "%{http_code} $f.$ext\n" \
      https://target.com/static/$f.$ext
  done
done

# 也可通过 Burp / DevTools Network 面板过滤 .map 后缀，观察是否返回 200
```

### 2. 批量下载 Source Map

```bash
mkdir -p /tmp/sourcemap_dump && cd /tmp/sourcemap_dump

# 下载单个 .map 文件
curl -O https://target.com/static/app.min.js.map

# wget 递归下载（谨慎，控制请求量）
wget -r -l 1 -A "*.map" --no-parent https://target.com/static/
```

### 3. 恢复源码

```bash
# 安装恢复工具（选其一）
npm install -g sourcemapper        # 命令行一键恢复
npm install -g reverse-sourcemap   # 备选

# sourcemapper（支持直接从 URL 拉取并解包）
sourcemapper --url https://target.com/static/app.min.js.map \
             --output /tmp/sourcemap_dump/src/

# reverse-sourcemap（本地 .map 文件）
reverse-sourcemap --output-dir /tmp/sourcemap_dump/src/ \
                  /tmp/sourcemap_dump/app.min.js.map
```

### 4. 在源码中搜索敏感信息

```bash
cd /tmp/sourcemap_dump/src/
grep -rEin "(api[_-]?key|secret|password|token|ak|sk)\s*[:=]\s*['\"][^'\"]{8,}" \
  --include="*.js" --include="*.ts" --include="*.vue" -n

# 搜索内网地址
grep -rEn '(192\.168\.|10\.\d+\.|172\.(1[6-9]|2\d|3[01])\.)' .
```

---

## JS Bundle 本地分析

当目标为纯前端 SPA（React/Vue/Angular 等），bundle 文件本身即为分析入口。

### 1. 枚举并下载 JS 资源

```bash
TARGET="https://target.com"
OUTDIR="/tmp/js_dump"
mkdir -p "$OUTDIR"

curl -s "$TARGET" | grep -oP 'src="[^"]+\.js[^"]*"' | \
  sed 's/src="//;s/"//' | while read path; do
    [[ "$path" == http* ]] && url="$path" || url="$TARGET$path"
    fname=$(basename "$path" | cut -d'?' -f1)
    echo "Downloading $url"
    curl -sL -o "$OUTDIR/$fname" "$url"
  done
```

### 2. 格式化混淆 JS

```bash
npm install -g js-beautify

for f in "$OUTDIR"/*.js; do
  js-beautify -o "${f%.js}.pretty.js" "$f"
done
```

### 3. 搜索敏感信息

```bash
cd "$OUTDIR"

# 云厂商 AK/SK 及通用 API Key
grep -rEn \
  '(accessKeyId|secretAccessKey|AKID|AppSecret|apiSecret|AK|SK)\s*[=:]\s*["'"'"'][A-Za-z0-9/+]{16,}' \
  *.pretty.js

# 内网/私有地址
grep -rEn '(192\.168\.|10\.\d+\.|172\.(1[6-9]|2\d|3[01])\.)' *.pretty.js

# 提取所有 URL（含接口路径，用于后续接口枚举）
grep -oEn 'https?://[^\s"'"'"'>]+' *.pretty.js | sort -u
```
