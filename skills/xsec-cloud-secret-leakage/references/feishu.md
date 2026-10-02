# 飞书密钥验证方法

> 官方文档：https://open.feishu.cn/document/server-docs/authentication-management/access-token/app-access-token-internal  
> 所有验证均为只读身份确认，不发送消息、不访问通讯录、不修改任何配置。

## 常见泄露场景

| 凭据类型 | 字段名 | 常见位置 |
|---------|--------|---------|
| 企业自建应用 AppID + AppSecret | `app_id`、`app_secret`、`feishu_app_id` | 前端 JS、移动端包体、配置接口 |
| 机器人 Webhook | `webhook_url`、`feishu_webhook` | 前端消息推送代码、CI/CD 配置 |
| user_access_token | `user_access_token`、`feishu_token` | 接口响应、LocalStorage |
| tenant_access_token | `tenant_access_token` | 接口响应、日志 |

## 禁止操作

| 禁止 | 原因 |
|------|------|
| 发送飞书机器人消息 | 向真实群组推送内容 |
| 获取通讯录 / 用户列表 | 下载真实组织架构和人员数据 |
| 调用审批 / 日历 / 多维表格写入 API | 影响真实业务数据 |
| 获取用户手机号 / 邮箱 | 获取真实用户隐私 |

## 验证步骤

### 企业自建应用：验证 AppID + AppSecret 有效性

```bash
# 获取 tenant_access_token（只读，不影响任何业务）
curl -s -X POST "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal" \
  -H "Content-Type: application/json" \
  -d '{"app_id":"<AppID>","app_secret":"<AppSecret>"}'

# 成功响应示例：
# {"code":0,"msg":"ok","tenant_access_token":"TOKEN","expire":7200}

# 失败响应示例：
# {"code":10003,"msg":"app not found"}
# {"code":10014,"msg":"app secret invalid"}
```

**注意：token 获取成功后立即丢弃，不得用于任何后续 API 调用。**

### 验证已泄露 tenant_access_token 是否有效

```bash
# 调用只读接口验证 token 有效性（获取当前应用信息，不访问用户数据）
curl -s -X GET "https://open.feishu.cn/open-apis/application/v6/applications/<AppID>" \
  -H "Authorization: Bearer <tenant_access_token>"

# 成功响应：{"code":0,"data":{"app":{"app_id":"...","status":...}}}
# 失败响应：{"code":99991663,"msg":"tenant_access_token invalid"}
```

### 验证已泄露 user_access_token 是否有效

```bash
# 获取当前登录用户基本信息（只读，只看身份，不获取手机号等隐私字段）
curl -s -X GET "https://open.feishu.cn/open-apis/authen/v1/user_info" \
  -H "Authorization: Bearer <user_access_token>"

# 成功响应：{"code":0,"data":{"name":"...","open_id":"..."}}
# 失败响应：{"code":99991663,"msg":"user_access_token invalid"}
```

### 机器人 Webhook 有效性

飞书机器人 Webhook 无需额外鉴权，URL 即凭据。  
验证方式：**由客户侧确认 Webhook URL 归属群组**，测试人员只记录 URL 中的 token 部分（脱敏），不发送任何实际消息。

## 结果解读

- `code:0` → AppID + AppSecret 有效，可调用该应用被授权的全部 API 权限，属高危。
- `code:10014` → AppSecret 错误，AppID 有效但 secret 已轮换，说明 AppID 归属可确认。
- `tenant_access_token` / `user_access_token` 验证有效 → 在有效期内可直接调用对应权限范围 API。
- 关键关注应用被授予的权限范围：通讯录读取、消息发送、多维表格读写、审批操作等均为高危。
