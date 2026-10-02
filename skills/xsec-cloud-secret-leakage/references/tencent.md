# 腾讯云 SecretId/SecretKey 验证命令

> 官方文档：https://cloud.tencent.com/document/product/440/34012  
> 所有操作均为只读，执行完毕后立即清除临时 profile。

## 禁止操作（腾讯云）

| 禁止 | 示例 |
|------|------|
| COS 写入/删除 | `cos upload`、`coscmd upload`、`coscmd delete` |
| COS 批量下载 | `coscmd download -r cos://bucket/ ./` |
| CVM 实例变更 | `cvm StartInstances`、`cvm TerminateInstances` |
| CAM 策略变更 | `cam CreatePolicy`、`cam AttachUserPolicy` |
| 密钥创建 | `cam CreateAccessKey` |
| KMS 解密业务密文 | `kms Decrypt` 对真实密文 |
| 跨账号扩展 | `sts AssumeRole` 到授权范围外角色 |

## 验证步骤

```bash
# 0. 安装 tccli（如未安装）
pip install tccli

# 1. 配置临时 profile
tccli configure --profile pentest-temp
# 按提示依次输入：SecretId、SecretKey、Region（如 ap-guangzhou）、json

# 临时凭据额外设置 Token
tccli configure set secretToken "<Token>" --profile pentest-temp

# 2. 验证身份有效性（返回 Uin / SubAccountUin / AccountId）
tccli sts GetCallerIdentity --profile pentest-temp

# 3. 查询绑定权限策略（只读）
tccli cam ListAttachedUserAllPolicies \
  --TargetUin "<Uin-from-GetCallerIdentity>" \
  --AttachType 0 --profile pentest-temp
tccli cam GetPolicy \
  --PolicyId <PolicyId> --profile pentest-temp

# 4. 确认 COS bucket 范围（只读，不下载）
tccli cos GetService --profile pentest-temp
tccli cos GetBucket --bucket <BucketName-AppId> \
  --max-keys 10 --profile pentest-temp

# 5. 清除临时 profile
rm -f ~/.tccli/pentest-temp.credential ~/.tccli/pentest-temp.configure
```

## 结果解读

- `GetCallerIdentity` 成功返回即说明凭据有效，`Uin` 为主账号或子账号 ID。
- `ListAttachedUserAllPolicies` 返回策略列表，`QcloudAdminFullAccess` 等全权策略属高危。
- `GetService` 返回可访问的 COS bucket 列表，记录名称和所在区域，不下载任何文件。
