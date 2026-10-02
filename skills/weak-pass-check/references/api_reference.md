# API 参考 — 弱口令检测技能

爆破脚本中常用库的快速参考。

---

## requests

```python
import requests

session = requests.Session()
session.verify = False  # 禁用 SSL 验证 (配合 urllib3.disable_warnings)

# POST 表单
resp = session.post(url, data={"user": "admin", "pass": "123"}, timeout=10)

# GET 请求
resp = session.get(url, params={"key": "value"}, timeout=10)

# 常用属性
resp.status_code   # 200, 429, 503 ...
resp.text          # 响应文本
resp.json()        # 解析 JSON
resp.content       # 原始字节 (用于验证码图片)
```

---

## pycryptodome — RSA

```python
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

# 从 Base64 DER 格式加载公钥 (jsencrypt 导出格式)
pubkey_der = base64.b64decode(PUBLIC_KEY_B64)
key = RSA.import_key(pubkey_der)
cipher = PKCS1_v1_5.new(key)
encrypted = cipher.encrypt(plaintext.encode("utf-8"))
result = base64.b64encode(encrypted).decode("utf-8")
```

---

## pycryptodome — AES

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

# AES-128-CBC (crypto-js 默认)
key = b"0123456789abcdef"   # 16 字节
iv  = b"0123456789abcdef"   # 16 字节
cipher = AES.new(key, AES.MODE_CBC, iv)
ct = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
result = base64.b64encode(ct).decode()
```

---

## gmssl — SM4 (国密)

```python
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT

sm4 = CryptSM4()
sm4.set_key(key_bytes, SM4_ENCRYPT)  # key: 16 字节
encrypted = sm4.crypt_cbc(iv_bytes, plaintext.encode())
```

---

## ddddocr — 图形验证码 OCR

```python
import ddddocr

# 单例模式 (全局只创建一次)
_OCR = None
def get_ocr():
    global _OCR
    if _OCR is None:
        _OCR = ddddocr.DdddOcr(show_ad=False)
    return _OCR

# 识别验证码
resp = session.get(captcha_url)
code = get_ocr().classification(resp.content)  # 返回字符串
```

---

## tqdm — 进度条

```python
from tqdm import tqdm

# 基础用法
with tqdm(total=len(payloads), unit="req", desc="爆破进度") as pbar:
    for payload in payloads:
        # ... 处理 ...
        pbar.update(1)
        pbar.set_postfix_str(f"当前密码: {payload['password']}")

# 在多线程中安全打印 (不打乱进度条)
tqdm.write(f"[+] 发现: {username}:{password}")
```

---

## threading — 线程本地 Session

```python
import threading

_thread_local = threading.local()

def get_session():
    """每个线程独立维护一个 requests.Session"""
    if not hasattr(_thread_local, "session"):
        s = requests.Session()
        s.verify = False
        s.headers.update({"User-Agent": random.choice(USER_AGENTS)})
        s.get(BASE_URL)  # 初始化 cookie
        _thread_local.session = s
    return _thread_local.session
```

---

## concurrent.futures — 多线程执行

```python
from concurrent.futures import ThreadPoolExecutor, as_completed

with ThreadPoolExecutor(max_workers=10) as executor:
    futures = {
        executor.submit(worker_fn, user, pwd): (user, pwd)
        for user in usernames
        for pwd in passwords
    }
    for future in as_completed(futures):
        user, pwd = futures[future]
        try:
            result = future.result()
        except Exception as e:
            logging.error(f"线程异常: {e}")
```

---

## 常见 HTTP 状态码处理

| 状态码 | 含义 | 处理策略 |
|--------|------|----------|
| 200 | 正常响应 | 检查响应体判断成功/失败 |
| 429 | 频率限制 | 指数退避 + 降低并发 |
| 503 | 服务不可用 | 同上 |
| 302 | 重定向 | 通常代表成功登录，检查 `Location` 头 |
| 403 | IP 封禁 | 停止，更换代理 |

---

## 字典加载

```python
def load_wordlist(filepath):
    """加载字典文件，忽略空行和注释行"""
    if not os.path.exists(filepath):
        sys.exit(f"字典文件不存在: {filepath}")
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]
```
