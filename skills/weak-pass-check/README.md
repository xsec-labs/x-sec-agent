# weak-pass-check

一个面向 GitHub Copilot Agent 的弱口令检测技能（Skill），可自动分析网站登录表单、识别加密方式，并生成可直接运行的 Python 爆破脚本。

## 功能特性

- 自动侦察登录表单结构（字段名、请求方式、接口地址）
- 识别前端加密算法：RSA / AES / SM2 / SM4
- 验证码处理：图形验证码（ddddocr OCR）、滑块验证码
- 账号锁定策略探测与绕过建议
- 用户名枚举检测
- 生成完整、可直接运行的 `brute_force.py` 脚本
- 内置本土化密码字典（中文弱口令、TOP 密码等）
- **社工字典生成**：基于目标信息自动生成定制化字典（账号/密码/组合），心理学驱动

## 安装

本 Skill 已内置在 xSecAgent 仓库的 `skills/weak-pass-check/`，无需从独立仓库安装。拉取本项目后即可被 `config/vulnerability-skills.yaml` 注册表引用。

## 使用方法

安装后，在 GitHub Copilot 对话中使用以下触发词即可激活技能：

- `弱口令`
- `爆破`
- `brute force`
- `login crack`
- `密码测试`
- `登录破解`
- `automated login testing`

**示例：**

```
帮我对 https://example.com/login 进行弱口令检测
```

Copilot 将自动完成以下步骤：

1. 访问目标登录页，分析表单结构与网络请求
2. 检测前端加密方式并提取密钥
3. 收集目标情报（邮箱、手机号、关键词等）
4. **自动生成社工字典**（基于心理学模式）
5. 分析验证码类型与绕过方案
6. 探测账号锁定策略
7. 生成定制化 `brute_force.py` 爆破脚本
8. 先以 `--test` 模式验证脚本逻辑，再执行完整爆破

## 目录结构

```
weak-pass-check/
├── SKILL.md                  # 技能主定义文件
├── assets/
│   └── wordlists/
│       ├── passwords/        # 密码字典
│       └── usernames/        # 用户名字典
├── references/
│   ├── api_reference.md              # API 参考
│   ├── encryption_patterns.md         # 加密特征识别指南
│   └── social_engineering_patterns.md # 社工密码心理学指南
└── scripts/
    ├── example.py                  # 爆破脚本模板
    └── social_engineering_dict.py  # 社工字典生成器
```

## 免责声明
