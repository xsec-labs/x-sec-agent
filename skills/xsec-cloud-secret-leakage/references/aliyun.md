# 阿里云 AK/SK 验证命令

> 官方文档：https://help.aliyun.com/document_detail/110244.html  
> 所有操作均为只读，执行完毕后立即清除临时 profile。

## 禁止操作（阿里云）

| 禁止 | 示例 |
|------|------|
| OSS 写入/删除 | `oss cp`、`ossutil rm`、`ossutil mb` |
| OSS 批量下载 | `ossutil sync`、`oss cp -r oss://bucket/ ./` |
| ECS 实例变更 | `ecs StopInstance`、`ecs DeleteInstance` |
| RAM 策略变更 | `ram CreatePolicy`、`ram AttachPolicyToUser` |
| 密钥创建 | `ram CreateAccessKey` |
| KMS 解密业务密文 | `kms Decrypt` 对真实密文 |
| 跨账号扩展 | `sts AssumeRole` 到授权范围外账号 |

## 验证步骤

```bash
# 1. 配置临时 profile（避免覆盖主配置）
aliyun configure --profile pentest-temp \
  --access-key-id "<AKID>" \
  --access-key-secret "<AKSecret>" \
  --region cn-hangzhou

# STS 临时凭据额外设置 SecurityToken
aliyun configure set --profile pentest-temp --sts-token "<SecurityToken>"

# 2. 验证身份有效性（返回 AccountId / UserId / Arn）
aliyun --profile pentest-temp sts GetCallerIdentity

# 3. 查询绑定权限策略（只读）
aliyun --profile pentest-temp ram ListPoliciesForUser \
  --UserName "<from-GetCallerIdentity>"
aliyun --profile pentest-temp ram GetPolicy \
  --PolicyName "<PolicyName>" --PolicyType Custom

# 4. 确认 OSS bucket 范围（只读，不下载任何文件）
aliyun --profile pentest-temp oss ls oss://
aliyun --profile pentest-temp oss ls oss://<bucket-name>/ --limit 5

# 5. 清除临时 profile
aliyun configure delete --profile pentest-temp
```

## 结果解读

- `GetCallerIdentity` 返回 `AccountId`、`UserId`、`Arn`，说明凭据有效。
- `ListPoliciesForUser` 返回的策略名称和类型用于判断权限范围，`AdministratorAccess` 或 `FullAccess` 类策略属高危。
- OSS `ls` 返回 bucket 数量及路径范围，用于确认可访问存储范围，不进入子目录、不下载文件。
