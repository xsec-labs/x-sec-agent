#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Social Engineering Dictionary Generator (社工字典生成器)
========================================================
基于目标信息和人类行为心理学模式，生成针对目标定制的社工字典。
用于弱口令检测流程中，在通用字典攻击之前优先尝试。

用法:
  python social_engineering_dict.py \
    --target "XSecAgent" \
    --domain "xsecagent.com" \
    --org "XSec Technology" \
    --recon-file recon_results.md \
    --output-dir ./social_dicts

输出:
  social_usernames.txt  用户名字典
  social_passwords.txt  密码字典
  social_combined.txt   用户名:密码 组合字典
  social_report.txt     生成报告
"""

import argparse
import re
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Set, Dict, Optional
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "scripts"))
from xsec_paths import resolve_artifact_path, resolve_output_path


# ═══════════════════════════════════════════════════════════════════════════
# 社工心理学词库
# ═══════════════════════════════════════════════════════════════════════════

# 数字后缀 — 人类倾向用简单递增数字
NUM_SUFFIXES = [
    '1', '12', '123', '1234', '12345', '123456', '12345678',
    '0', '00', '000', '0000',
    '111', '222', '333', '444', '555', '666', '777', '888', '999',
    '111111', '666666', '888888', '88888888',
]

# 中国情感/幸运数字（心理学：情感锚定）
LUCKY_NUMBERS = ['520', '521', '1314', '168', '888', '666', '999', '5201314']

# 特殊符号后缀（复杂度最小努力策略）
SPECIAL_SUFFIXES = [
    '!', '@', '#', '$', '%',
    '@123', '#123', '!@#', '!123',
    '.', '_', '-', '.com', '.cn',
]

# 月份
MONTHS_EN = [
    'january', 'february', 'march', 'april', 'may', 'june',
    'july', 'august', 'september', 'october', 'november', 'december',
    'jan', 'feb', 'mar', 'apr', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec',
]
MONTHS_CN = [
    'yiyue', 'eryue', 'sanyue', 'siyue', 'wuyue', 'liuyue',
    'qiyue', 'bayue', 'jiuyue', 'shiyue', 'shiyiyue', 'shieryue',
]

# 季节（季度密码更新心理）
SEASONS = ['spring', 'summer', 'autumn', 'winter',
            'chun', 'xia', 'qiu', 'dong']

# 键盘行走（肌肉记忆）
KEYBOARD_WALKS = [
    'qwerty', 'qwertyuiop',
    'asdfgh', 'asdfghjkl',
    'zxcvbnm',
    '1qaz2wsx', '1q2w3e4r',
    'qazwsx', 'qweasd', 'qweasdzxc',
    'zaqxsw',
    '!QAZ2wsx', '1qaz@WSX',
]

# 人类基础词根（熟悉性启发式）
HUMAN_ROOT_WORDS = [
    'admin', 'root', 'sa', 'user', 'guest', 'test', 'dev',
    'system', 'manager', 'master', 'operator', 'service',
    'love', 'happy', 'hello', 'world', 'sunshine',
    'freedom', 'dream', 'winner', 'success',
    'woaini', 'iloveyou', 'forever', 'missyou',
    'password', 'passwd', 'p@ssw0rd', 'P@ssw0rd',
    'welcome', 'default', 'backup', 'temp', 'demo',
    'red', 'blue', 'green', 'black', 'white',
    'dragon', 'tiger', 'lion', 'cat', 'dog',
    'apple', 'orange',
    'oracle', 'mysql', 'linux', 'windows', 'apache', 'nginx',
    'redis', 'docker', 'git', 'python', 'java', 'node',
    'wordpress', 'jira', 'github', 'gitlab',
]

# Leet 替换表（小聪明式安全感觉）
LEET_MAP = {
    'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$',
    't': '7', 'l': '1', 'b': '8', 'g': '9',
}

# 常见管理用户名
COMMON_ADMIN_USERS = [
    'admin', 'root', 'sa', 'sysadmin', 'webmaster',
    'info', 'support', 'service', 'test', 'dev',
    'user', 'guest', 'demo', 'manager', 'operator',
]


class SEDictGenerator:
    """社工字典生成器"""

    def __init__(
        self,
        target_name: str = '',
        domain: str = '',
        org_name: str = '',
        recon_data: Optional[Dict] = None,
        names: Optional[List[str]] = None,
        emails: Optional[List[str]] = None,
        phones: Optional[List[str]] = None,
        keywords: Optional[List[str]] = None,
        output_dir: str = '.',
    ):
        self.target_name = target_name
        self.domain = domain
        self.org_name = org_name
        self.recon_data = recon_data or {}
        self.output_dir = output_dir

        # 情报字段
        self.names: List[str] = list(set(names or []))
        self.emails: List[str] = list(set(emails or []))
        self.phones: List[str] = list(set(phones or []))
        self.keywords: List[str] = list(set(keywords or []))

        # 从侦察数据中提取额外信息
        self._extract_from_recon()

        # 词根池
        self.base_words: List[str] = []
        self._build_base_word_pool()

        # 统计
        self.stats: Dict[str, int] = defaultdict(int)

    # ── 情报提取 ──

    def _extract_from_recon(self):
        if not self.recon_data:
            return

        raw_text = ''
        for key, val in self.recon_data.items():
            if isinstance(val, str):
                raw_text += val + '\n'
                found_emails = re.findall(r'[\w\.-]+@[\w\.-]+\.[a-zA-Z]{2,}', val)
                self.emails.extend(found_emails)
                found_phones = re.findall(r'1[3-9]\d{9}', val)
                self.phones.extend(found_phones)
                found_names = re.findall(
                    r'(?:name|user|author|contact)[\s:：=]+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)',
                    val, re.IGNORECASE
                )
                self.names.extend(found_names)
            elif isinstance(val, list):
                raw_text += ' '.join(str(v) for v in val) + '\n'
                kl = key.lower()
                if any(n in kl for n in ('name', '姓名')):
                    self.names.extend([str(v) for v in val])
                elif any(e in kl for e in ('email', '邮箱', 'mail')):
                    self.emails.extend([str(v) for v in val])
                elif any(p in kl for p in ('phone', 'tel', '电话', '手机')):
                    self.phones.extend([str(v) for v in val])
                elif any(k in kl for k in ('keyword', 'key', '关键词')):
                    self.keywords.extend([str(v) for v in val])

        # 去重
        self.names = list(set(self.names))
        self.emails = list(set(self.emails))
        self.phones = list(set(self.phones))
        self.keywords = list(set(self.keywords))

    # ── 词根池 ──

    def _build_base_word_pool(self):
        words = set()

        # 域名拆分
        if self.domain:
            for part in self.domain.lower().split('.'):
                if part not in ('com', 'cn', 'net', 'org', 'gov', 'edu', 'io',
                                'co', 'cc', 'me', 'info', 'biz', 'top', 'xyz'):
                    clean = re.sub(r'[^a-zA-Z0-9]', '', part)
                    if clean:
                        words.add(clean)
                        words.add(clean.lower())
                        words.add(clean.upper())
                        words.add(clean.capitalize())
                        words.add(clean[::-1])

        # 组织名
        if self.org_name:
            clean_org = re.sub(r'[^a-zA-Z0-9\u4e00-\u9fff]', '', self.org_name)
            if clean_org:
                words.add(clean_org)
                words.add(clean_org.lower())
            abbr = ''.join([w[0] for w in self.org_name.split()
                          if w and w[0].isalpha()])
            if len(abbr) >= 2:
                words.add(abbr)
                words.add(abbr.lower())
            for w in self.org_name.split():
                clean = re.sub(r'[^a-zA-Z0-9]', '', w)
                if len(clean) >= 2:
                    words.add(clean)
                    words.add(clean.lower())

        # 目标名
        if self.target_name:
            clean_t = re.sub(r'[^a-zA-Z0-9]', '', self.target_name)
            if clean_t:
                words.add(clean_t)
                words.add(clean_t.lower())

        # 邮箱 local-part
        for email in self.emails:
            if '@' in email:
                local = email.split('@')[0]
                words.add(local)
                words.add(local.lower())
                words.add(local.replace('.', ''))
                if '.' in local:
                    words.add(local.split('.')[0])

        # 人名
        for name in self.names:
            clean = re.sub(r'[^a-zA-Z]', '', name)
            if clean and len(clean) >= 2:
                words.add(clean)
                words.add(clean.lower())

        # 关键词
        for kw in self.keywords:
            clean = re.sub(r'[^a-zA-Z0-9]', '', kw)
            if clean and len(clean) >= 2:
                words.add(clean)
                words.add(clean.lower())

        self.base_words = sorted(
            [w for w in words if 2 <= len(w) <= 50 and not w.isdigit()],
            key=lambda x: (len(x), x)
        )

    # ── 用户名生成 ──

    def gen_usernames(self) -> List[str]:
        usernames: Set[str] = set()

        # 邮箱
        for email in self.emails:
            if '@' in email:
                local = email.split('@')[0]
                usernames.add(local)
                usernames.add(local.lower())
                nodot = local.replace('.', '')
                if nodot != local:
                    usernames.add(nodot)
                    usernames.add(nodot.lower())
                if '.' in local:
                    usernames.add(local.split('.')[0])

        # 关键词/域名 + 前缀
        for word in self.base_words[:50]:
            w = word.lower()
            if len(w) >= 2 and not w.isdigit():
                usernames.add(w)
                for prefix in COMMON_ADMIN_USERS[:8]:
                    usernames.add(f"{prefix}_{w}")
                    usernames.add(f"{prefix}{w}")

        # 域名上下文
        if self.domain:
            ds = self.domain.split('.')[0]
            for base in COMMON_ADMIN_USERS[:6]:
                usernames.add(f"{base}@{self.domain}")
                usernames.add(f"{base}_{ds}")

        # 人名
        for name in self.names:
            clean = re.sub(r'[^a-zA-Z]', '', name)
            if clean:
                usernames.add(clean)
                usernames.add(clean.lower())

        # 手机号
        for phone in self.phones:
            usernames.add(phone)
            if len(phone) >= 11:
                usernames.add(phone[-6:])
                usernames.add(phone[-8:])

        # 通用管理用户名
        for u in COMMON_ADMIN_USERS:
            usernames.add(u)

        result = sorted(
            [u for u in usernames if 1 <= len(u) <= 64],
            key=lambda x: (not x[0].isalpha(), x.lower())
        )

        self.stats['usernames_generated'] = len(result)
        return result

    # ── 密码生成 ──

    def _apply_leet(self, word: str) -> List[str]:
        variants = []
        leeted = ''.join(LEET_MAP.get(c.lower(), c) for c in word)
        if leeted != word:
            variants.append(leeted)
        return variants

    def gen_passwords(self) -> List[str]:
        passwords: Set[str] = set()
        current_year = datetime.now().year
        years = [str(y) for y in range(current_year - 10, current_year + 2)]

        all_words = list(set(self.base_words + HUMAN_ROOT_WORDS))

        # 1. 词根直接使用
        for word in all_words:
            if 4 <= len(word) <= 32:
                passwords.add(word)
                passwords.add(word.lower())
                rev = word[::-1]
                if rev != word and 4 <= len(rev) <= 32:
                    passwords.add(rev)

        # 2. 词根 + 数字后缀
        candidate = self.base_words[:30] + HUMAN_ROOT_WORDS[:15]
        for word in candidate:
            wl = word.lower()
            for num in NUM_SUFFIXES[:10]:
                passwords.add(f"{word}{num}")
                passwords.add(f"{wl}{num}")
            for num in LUCKY_NUMBERS:
                passwords.add(f"{word}{num}")
                passwords.add(f"{wl}{num}")

        # 3. 词根 + 年份
        for word in candidate[:20]:
            for y in years[-5:]:
                passwords.add(f"{word}{y}")
                passwords.add(f"{word}@{y}")
                passwords.add(f"{word}_{y}")

        # 4. 词根 + 特殊符号
        for word in candidate[:20]:
            for sym in SPECIAL_SUFFIXES[:8]:
                passwords.add(f"{word}{sym}")

        # 5. 首字母大写变体
        for word in candidate[:15]:
            if word[0].isalpha():
                cap = word[0].upper() + word[1:].lower()
                passwords.add(f"{cap}123")
                passwords.add(f"{cap}@{current_year}")
                passwords.add(f"{cap}123!@#")

        # 6. Leet 替换
        for word in candidate[:10]:
            for variant in self._apply_leet(word):
                passwords.add(variant)
                passwords.add(f"{variant}123")

        # 7. 键盘行走
        for kp in KEYBOARD_WALKS:
            passwords.add(kp)
            passwords.add(f"{kp}123")
            passwords.add(f"{kp}!")

        # 8. 日期模式
        for y in range(current_year - 5, current_year + 2):
            for m in range(1, 13):
                passwords.add(f"{y}{m:02d}")
                for d in (1, 15, 28):
                    passwords.add(f"{y}{m:02d}{d:02d}")

        # 9. 手机号派生
        for phone in self.phones:
            if len(phone) >= 11:
                passwords.add(phone[-6:])
                passwords.add(phone[-8:])
            passwords.add(phone)

        # 10. 中国特有模式
        for root in ['admin', 'root', 'test']:
            for lucky in LUCKY_NUMBERS:
                passwords.add(f"{root}{lucky}")
            passwords.add(f"{root}888")
            passwords.add(f"{root}666")
            passwords.add(f"{root}888888")

        if self.domain:
            ds = self.domain.split('.')[0]
            passwords.add(f"{ds}520")
            passwords.add(f"{ds}888")
            passwords.add(f"{ds}666")
            passwords.add(f"{ds}1314")

        # 11. 多词根拼接
        if len(self.base_words) >= 2:
            for i, w1 in enumerate(self.base_words[:5]):
                for w2 in self.base_words[i+1:i+5]:
                    if w1 != w2:
                        for sep in ('', '_', '-', '@', '.'):
                            combined = f"{w1}{sep}{w2}"
                            if 4 <= len(combined) <= 32:
                                passwords.add(combined)
                                passwords.add(f"{combined}123")

        # 12. 季节 + 年份
        for s in SEASONS:
            for y in years[-3:]:
                passwords.add(f"{s}{y}")
                passwords.add(f"{s.capitalize()}{y}")

        # 13. 月份 + 年份
        for m in MONTHS_EN:
            for y in years[-3:]:
                passwords.add(f"{m}{y}")
                passwords.add(f"{m.capitalize()}{y}")

        # 14. 人类基础词 + 年份/数字
        for word in HUMAN_ROOT_WORDS[:20]:
            for y in years[-3:]:
                passwords.add(f"{word}{y}")
                passwords.add(f"{word}{y}!")
            passwords.add(f"{word}123456")
            passwords.add(f"{word}@123")

        # 过滤
        passwords = {
            p for p in passwords
            if 4 <= len(p) <= 32 and all(32 <= ord(c) < 127 for c in p)
        }

        result = sorted(passwords)
        self.stats['passwords_generated'] = len(result)
        return result

    # ── 组合字典 ──

    def gen_combined(self) -> List[str]:
        usernames = self.gen_usernames()
        passwords_set = set(self.gen_passwords())

        combinations: List[str] = []

        # 优先: 用户名 = 密码
        for u in usernames:
            if u in passwords_set:
                combinations.append(f"{u}:{u}")

        # 用户名 + 常见后缀
        for u in usernames[:50]:
            for num in ('', '123', '123456', '888', '666', '520', '1314',
                        '@123', '!', '@2024', '@2025'):
                pwd = f"{u}{num}"
                if 4 <= len(pwd) <= 32:
                    combinations.append(f"{u}:{pwd}")

        # 通用管理用户 × 社工密码 Top 200
        admin_users = [u for u in COMMON_ADMIN_USERS if u in usernames]
        if not admin_users:
            admin_users = COMMON_ADMIN_USERS[:5]
        top_pwds = sorted([
            p for p in passwords_set
            if not p.isdigit() and len(p) >= 5
        ])[:200]
        for u in admin_users:
            for p in top_pwds[:100]:
                combinations.append(f"{u}:{p}")

        # 手机号 × 密码
        phone_users = [u for u in usernames if u.isdigit() and len(u) >= 11][:5]
        for u in phone_users:
            for p in top_pwds[:50]:
                combinations.append(f"{u}:{p}")

        # 去重
        seen = set()
        unique = []
        for c in combinations:
            if c not in seen:
                seen.add(c)
                unique.append(c)

        self.stats['combined_generated'] = len(unique)
        return unique

    # ── 主入口 ──

    def generate(self, modes: List[str] = None):
        if modes is None:
            modes = ['usernames', 'passwords', 'combined']

        os.makedirs(self.output_dir, exist_ok=True)
        files_written = []

        if 'usernames' in modes:
            usernames = self.gen_usernames()
            path = os.path.join(self.output_dir, 'social_usernames.txt')
            with open(path, 'w', encoding='utf-8') as f:
                for u in usernames:
                    f.write(f"{u}\n")
            files_written.append((path, len(usernames)))

        if 'passwords' in modes:
            passwords = self.gen_passwords()
            path = os.path.join(self.output_dir, 'social_passwords.txt')
            with open(path, 'w', encoding='utf-8') as f:
                for p in passwords:
                    f.write(f"{p}\n")
            files_written.append((path, len(passwords)))

        if 'combined' in modes:
            combined = self.gen_combined()
            path = os.path.join(self.output_dir, 'social_combined.txt')
            with open(path, 'w', encoding='utf-8') as f:
                for c in combined:
                    f.write(f"{c}\n")
            files_written.append((path, len(combined)))

        # 报告
        self._write_report()

        return files_written

    def _write_report(self):
        path = os.path.join(self.output_dir, 'social_report.txt')
        lines = []
        lines.append("=" * 55)
        lines.append("  社工字典生成报告")
        lines.append("=" * 55)
        lines.append(f"  生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"  目标标识: {self.target_name or 'N/A'}")
        lines.append(f"  目标域名: {self.domain or 'N/A'}")
        lines.append(f"  组织名称: {self.org_name or 'N/A'}")
        lines.append("")
        lines.append("── 情报统计 ──")
        lines.append(f"  邮箱:     {len(self.emails)} 个")
        lines.append(f"  手机号:   {len(self.phones)} 个")
        lines.append(f"  人名:     {len(self.names)} 个")
        lines.append(f"  关键词:   {len(self.keywords)} 个")
        lines.append(f"  词根池:   {len(self.base_words)} 个")
        lines.append("")
        lines.append("── 生成统计 ──")
        lines.append(f"  用户名字典:   {self.stats.get('usernames_generated', 0):,} 条")
        lines.append(f"  密码字典:     {self.stats.get('passwords_generated', 0):,} 条")
        lines.append(f"  组合字典:     {self.stats.get('combined_generated', 0):,} 条")
        lines.append("")
        lines.append("── 攻击策略建议 ──")
        lines.append("  1. 先用 social_combined.txt 精准爆破（<1万条，命中率最高）")
        lines.append("  2. 再用 social_passwords.txt 喷洒（配合用户名枚举结果）")
        lines.append("  3. 最后用通用字典全面爆破")
        lines.append("=" * 55)
        with open(path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines) + '\n')


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════

def parse_args():
    parser = argparse.ArgumentParser(
        description='Social Engineering Dictionary Generator (社工字典生成器)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 基础用法
  python social_engineering_dict.py -t XSecAgent -d xsecagent.com -o "XSec Inc"

  # 完整用法
  python social_engineering_dict.py -t XSecAgent -d xsecagent.com \\
    -o "XSec Inc" -r recon_results.md --names "Zhang San" \\
    --emails admin@xsecagent.com --phones 13800138000 \\
    --keywords security firewall -O ./social_dicts --mode combined
        """,
    )
    parser.add_argument('--target', '-t', default='', help='目标标识/名称')
    parser.add_argument('--domain', '-d', default='', help='目标域名')
    parser.add_argument('--org', '-o', default='', help='组织/公司名称')
    parser.add_argument('--recon-file', '-r', default='', help='侦察结果文件（JSON/Markdown）')
    parser.add_argument('--names', '-n', nargs='*', default=[], help='人名列表')
    parser.add_argument('--emails', '-e', nargs='*', default=[], help='邮箱列表')
    parser.add_argument('--phones', '-p', nargs='*', default=[], help='手机号列表')
    parser.add_argument('--keywords', '-k', nargs='*', default=[], help='额外关键词')
    parser.add_argument('--output-dir', '-O', default='./social_dicts', help='输出目录')
    parser.add_argument('--mode', '-m',
                        choices=['usernames', 'passwords', 'combined', 'all'],
                        default='all', help='生成模式 (默认: all)')
    return parser.parse_args()


def load_recon_file(filepath: str) -> Dict:
    if not filepath:
        return {}
    recon_path = resolve_artifact_path(filepath)
    if not recon_path.exists():
        return {}
    with open(recon_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass
    # Markdown 解析：按 ## 章节拆分
    data = {'raw': content}
    current = '_preamble'
    for line in content.split('\n'):
        ls = line.strip()
        if not ls:
            continue
        if ls.startswith('## ') or ls.startswith('### '):
            current = ls.lstrip('#').strip().lower()
            continue
        data[current] = data.get(current, '') + ls + '\n'
    return data


def main():
    args = parse_args()
    recon_data = load_recon_file(args.recon_file)
    output_dir = str(resolve_output_path(args.output_dir))

    mode_map = {
        'all': ['usernames', 'passwords', 'combined'],
        'usernames': ['usernames'],
        'passwords': ['passwords'],
        'combined': ['combined'],
    }
    modes = mode_map[args.mode]

    gen = SEDictGenerator(
        target_name=args.target,
        domain=args.domain,
        org_name=args.org,
        recon_data=recon_data,
        names=args.names,
        emails=args.emails,
        phones=args.phones,
        keywords=args.keywords,
        output_dir=output_dir,
    )

    print(f"\n[*] 社工字典生成器")
    print(f"    目标: {args.target or 'N/A'}")
    print(f"    域名: {args.domain or 'N/A'}")
    print(f"    词根: {len(gen.base_words)} 个")
    print(f"    输出: {output_dir}/\n")

    files = gen.generate(modes)
    total = 0
    for fp, cnt in files:
        print(f"  [+] {os.path.basename(fp):<30} {cnt:>8,} 条")
        total += cnt
    print(f"\n  [*] 总计: {total:,} 条")
    print(f"  [*] 报告: {os.path.join(output_dir, 'social_report.txt')}\n")


if __name__ == '__main__':
    main()
