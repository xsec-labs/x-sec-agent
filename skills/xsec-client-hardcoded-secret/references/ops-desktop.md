# 桌面客户端实操：Electron / Windows / macOS

## Electron 应用（asar 解包）

Electron 应用将所有前端+Node.js 代码打包在 `app.asar` 中，解包后等同于分析完整 JS 源码树。

```bash
# 安装 asar 工具
npm install -g @electron/asar

# macOS：找到 app.asar 位置
find /Applications/TargetApp.app -name "app.asar" 2>/dev/null

# 解包
mkdir /tmp/electron_out
asar extract /Applications/TargetApp.app/Contents/Resources/app.asar \
             /tmp/electron_out/

# 搜索敏感信息
cd /tmp/electron_out

# 通用 Key / Secret / Token
grep -rEin \
  '(api[_-]?key|secret|password|token|ak|sk|accesskey|appid)\s*[=:]\s*["'"'"'][^"'"'"']{6,}' \
  --include="*.js" --include="*.json" --include="*.env"

# 数据库连接字符串
grep -rEin \
  '(mongodb://|mysql://|postgresql://|redis://)[^\s"'"'"']+' \
  --include="*.js" --include="*.json"

# 内网端点
grep -rEin \
  '(http://192\.|http://10\.|http://172\.|localhost:[0-9]{4,5})' \
  --include="*.js"
```

---

## Windows 安装包（NSIS / Squirrel .exe）

```bash
# 提取 NSIS 安装包（需 7-Zip）
7z x target-installer.exe -o/tmp/nsis_out/

# 找到 asar 或 app.zip
find /tmp/nsis_out/ -name "*.asar" -o -name "app.zip" | head -5

# 若为 app.zip 形式
unzip /tmp/nsis_out/resources/app.zip -d /tmp/electron_win_out/

# 之后按 Electron 流程搜索
```

---

## macOS DMG / PKG

```bash
# 挂载 DMG
hdiutil attach target.dmg

# 复制 .app 到本地
cp -r /Volumes/TargetApp/TargetApp.app /tmp/

# 卸载
hdiutil detach /Volumes/TargetApp/

# 按 Electron 流程分析 app.asar
find /tmp/TargetApp.app -name "app.asar"
asar extract /tmp/TargetApp.app/Contents/Resources/app.asar /tmp/electron_out/
```
