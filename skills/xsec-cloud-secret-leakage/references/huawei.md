# 华为云 AK/SK 验证命令

> 官方文档：https://support.huaweicloud.com/hcloud_cli/  
> 所有操作均为只读，执行完毕后立即清除临时配置。

## 禁止操作（华为云）

| 禁止 | 示例 |
|------|------|
| OBS 写入/删除 | `obsutil cp`、`obsutil rm` |
| OBS 批量下载 | `obsutil sync obs://bucket/ ./` |
| ECS 实例变更 | `ecs BatchStartServers`、`ecs DeleteServer` |
| IAM 策略变更 | `iam CreatePolicy`、`iam AttachRolePolicy` |
| 密钥创建 | `iam CreatePermanentAccessKey` |
| 跨账号扩展 | `iam CreateTemporaryAccessKeyByAgency` 到授权范围外 |

## 验证步骤

```bash
# 0. 安装 hcloud CLI
# 参考：https://support.huaweicloud.com/hcloud_cli/

# 1. 配置临时认证（单独配置文件，避免覆盖主配置）
hcloud configure init --cli-profile pentest-temp

# 2. 验证身份有效性
# 查询当前 AK 对应密钥信息（长期凭据）
hcloud IAM ShowPermanentAccessKey \
  --cli-profile pentest-temp \
  --access-key-id "<AccessKeyId>"

# 查询当前账号信息
hcloud IAM ShowCredential --cli-profile pentest-temp

# 3. 查询绑定权限范围（只读）
# 列出账号下已授权的项目
hcloud IAM ListAuthProjectsDetail --cli-profile pentest-temp

# 列出当前用户组绑定的策略
hcloud IAM ListGroupsForUser --cli-profile pentest-temp

# 4. 确认 OBS bucket 范围（只读，不下载）
# 需安装 obsutil：https://support.huaweicloud.com/obsutil/
obsutil ls -config=/tmp/pentest-obs.properties
# 其中 pentest-obs.properties 内容：
# [CrentialSection]
# accessKey=<AK>
# secretKey=<SK>
# endPoint=obs.cn-north-4.myhuaweicloud.com

# 5. 清除临时配置
rm -f ~/.hcloud/pentest-temp.json /tmp/pentest-obs.properties
```

## 结果解读

- `ShowPermanentAccessKey` 成功返回说明 AK 有效，注意 `status` 字段（active/inactive）。
- `ListAuthProjectsDetail` 返回账号可访问的项目范围，项目越多代表影响面越广。
- OBS `ls` 返回可访问的 bucket 列表，记录名称和区域，不进入桶内、不下载文件。
