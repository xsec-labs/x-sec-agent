# 钉钉密钥验证方法

> 官方文档：https://open.dingtalk.com/document/orgapp/obtain-orgapp-token  
> 所有验证均为只读身份确认，不发送消息、不访问通讯录、不修改任何配置。

## 常见泄露场景

| 凭据类型 | 字段名 | 常见位置 |
|---------|--------|---------|
| 企业内部应用 AppKey + AppSecret | `appKey`、`appSecret`、`dingtalk_app_key` | 前端 JS、移动端包体、配置接口 |
| 机器人 Webhook + Secret | `webhook`、`robot_token`、`sign_secret` | 前端消息推送代码、CI/CD 配置 |
| 旧版 CorpId + CorpSecret | `corp_id`、`corp_secret` | 遗留后台配置、日志 |
| 个人 accessToken | `access_token`、`dingtalk_token` | 接口响应、浏览器存储 |

## 禁止操作

| 禁止 | 原因 |
|------|------|
| 发送钉钉机器人消息 | 向真实群组推送内容 |
| 获取通讯录 / 员工列表 | 下载真实组织架构和人员数据 |
| 调用 OA 审批 / 打卡 API | 影响真实业务流程 |
| 获取用户 unionId / 手机号 | 获取真实用户隐私 |

## 验证步骤

### 企业内部应用：验证 AppKey + AppSecret 有效性

```bash
# 获取企业内部应用 access_token（只读，不影响任何业务）
curl -s -X POST "https://oapi.dingtalk.com/gettoken" \
  -H "Content-Type: application/json" \
  -d '{"appkey":"<AppKey>","appsecret":"<AppSecret>"}'

# 成功响应示例：
# {"errcode":0,"errmsg":"ok","access_token":"TOKEN","expires_in":7200}

# 失败响应示例：
# {"errcode":40078,"errmsg":"invalid appkey or appSecret"}
```

**注意：access_token 获取成功后立即丢弃，不得用于任何后续 API 调用。**

### 验证已泄露 access_token 是否有效

```bash
# 调用只读的 getJsapiTicket（验证 token 有效性，不访问用户/组织数据）
curl -s "https://oapi.dingtalk.com/get_jsapi_ticket?access_token=<TOKEN>"

# 成功响应：{"errcode":0,"errmsg":"ok","ticket":"...","expires_in":7200}
# 失败响应：{"errcode":88,"errmsg":"token expired or invalid"}
```

### 机器人 Webhook 有效性

机器人 Webhook 地址本身即为凭据，无需额外 secret 即可直接调用。  
验证方式：**由客户侧确认 Webhook URL 归属群组**，测试人员只记录 URL 中的 token 前缀，不发送任何实际消息。

如 Webhook 附加了签名校验（`sign_secret`），验证有效性同样只记录字段存在，不构造签名请求。

### 旧版 CorpId + CorpSecret

```bash
# 获取企业 access_token（旧版接口）
curl -s "https://oapi.dingtalk.com/gettoken?corpid=<CorpId>&corpsecret=<CorpSecret>"

# 响应格式与企业内部应用相同
```

## 结果解读

- `errcode:0` → AppKey/AppSecret 或 CorpId/CorpSecret 有效，可调用全量企业 API，属高危。
- 若 access_token 可用，关键关注后续可调用的权限范围：通讯录读取、OA 操作、考勤、审批等均为高危。
- 机器人 Webhook 泄露即可被任意主体向该群推送消息，属中高危。
