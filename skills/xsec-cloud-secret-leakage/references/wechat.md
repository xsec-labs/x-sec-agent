# 微信公众号 / 小程序密钥验证方法

> 官方文档：  
> - 公众号：https://developers.weixin.qq.com/doc/offiaccount/Basic_Information/Get_access_token.html  
> - 小程序：https://developers.weixin.qq.com/miniprogram/dev/OpenApiDoc/mp-access-token/getAccessToken.html  
> 所有验证均为只读身份确认，不发送消息、不修改配置、不访问用户数据。

## 常见泄露场景

| 凭据类型 | 字段名 | 常见位置 |
|---------|--------|---------|
| 公众号 AppID + AppSecret | `appid`、`appsecret`、`app_secret` | 前端配置、JS bundle、小程序包体 |
| 小程序 AppID + AppSecret | 同上 | 反编译小程序包（`.wxapkg`） |
| 微信支付 MchID + APIKey | `mch_id`、`api_key`、`pay_key` | 支付初始化接口、配置文件 |
| 服务端 access_token | `access_token` | 接口返回、日志 |

## 禁止操作

| 禁止 | 原因 |
|------|------|
| 发送模板消息 / 客服消息 | 向真实用户发送骚扰内容 |
| 获取用户列表 / openid 列表 | 下载真实用户数据 |
| 修改菜单 / 自定义回复 | 篡改公众号配置 |
| 获取微信支付退款 / 关单 | 影响真实交易 |
| 使用 code2Session 换取真实用户 session | 获取真实用户隐私 |

## 验证步骤

### 公众号 / 小程序：验证 AppID + AppSecret 有效性

```bash
# 尝试获取 access_token（HTTP 请求，只读，不影响任何业务）
curl -s "https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=<AppID>&secret=<AppSecret>"

# 成功响应示例：
# {"access_token":"TOKEN_VALUE","expires_in":7200}

# 失败响应示例（无效凭据）：
# {"errcode":40013,"errmsg":"invalid appid"}
# {"errcode":40125,"errmsg":"invalid appsecret"}
```

**注意：access_token 获取成功后立即丢弃，不得用于后续任何 API 调用。**

### 验证已泄露 access_token 是否仍有效

```bash
# 使用 getApiDomainIp 接口验证（只读，返回 IP 白名单，不访问用户数据）
curl -s "https://api.weixin.qq.com/cgi-bin/get_api_domain_ip?access_token=<TOKEN>"

# 成功响应：{"ip_list":["..."]}
# 失败响应：{"errcode":40001,"errmsg":"invalid credential"}
```

### 小程序：识别 AppID 归属

```bash
# 通过微信开放平台接口查询小程序基本信息（无需 secret，只用 AppID）
# 实际归属查询由客户侧通过微信开放平台后台确认
# 测试人员记录 AppID 前缀：wx 开头为公众平台，以此区分公众号（gh_前缀）与小程序
echo "<AppID>" | grep -oE "^wx[a-f0-9]{16}"
```

### 微信支付 MchID + APIKey 有效性

微信支付 v2 APIKey 无官方只读验证接口，风险判断依据：
- APIKey 长度固定 32 位，全为字母数字混合
- 确认 MchID 与 AppID 配对关系（由客户侧通过商户平台确认）
- **不得发起任何支付、退款、查单、关单请求**

## 结果解读

- `access_token` 获取成功 → AppID + AppSecret 均有效，可调用全量公众号/小程序 API，属高危。
- 返回 `errcode:40013` → AppID 无效或不存在。
- 返回 `errcode:40125` → AppSecret 错误，AppID 有效但 secret 已轮换。
- 已泄露的 `access_token` 验证有效 → 该 token 在有效期内（最长 7200 秒），可直接调用 API，属高危。
