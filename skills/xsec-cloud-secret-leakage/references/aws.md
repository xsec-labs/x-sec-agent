# AWS AK/SK 验证命令

> 官方文档：https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html  
> 所有操作均为只读，执行完毕后立即清除临时 profile。

## 禁止操作（AWS）

| 禁止 | 示例 |
|------|------|
| S3 写入/删除 | `aws s3 cp`、`aws s3 rm`、`aws s3api put-object` |
| S3 批量下载 | `aws s3 sync s3://bucket/ ./` |
| EC2 实例变更 | `aws ec2 start/stop/terminate-instances` |
| IAM 策略变更 | `aws iam create-policy`、`aws iam attach-*-policy` |
| 密钥创建 | `aws iam create-access-key` |
| KMS 解密业务密文 | `aws kms decrypt` 对真实密文 |
| 主机登录 | `aws ssm start-session` |
| 跨账号扩展 | `aws sts assume-role` 到授权范围外账号 |

## 验证步骤

```bash
# 1. 配置临时 profile（避免覆盖默认配置）
aws configure --profile pentest-temp
# 按提示依次输入：Access Key ID、Secret Access Key、Region（如 cn-north-1）、json

# STS 临时凭据额外设置 session token
aws configure set aws_session_token "<SessionToken>" --profile pentest-temp

# 2. 验证身份有效性（返回 Account / UserId / Arn）
aws sts get-caller-identity --profile pentest-temp

# 3. 查询绑定权限策略（只读）
# 普通用户
aws iam list-attached-user-policies \
  --user-name "<UserName>" --profile pentest-temp
# STS 角色
aws iam list-attached-role-policies \
  --role-name "<RoleName>" --profile pentest-temp
# 模拟权限检查（不执行任何实际动作）
aws iam simulate-principal-policy \
  --policy-source-arn "<Arn-from-get-caller-identity>" \
  --action-names "s3:ListAllMyBuckets" "ec2:DescribeInstances" \
  --profile pentest-temp

# 4. 确认 S3 bucket 范围（只读，不下载）
aws s3 ls --profile pentest-temp
aws s3 ls s3://<bucket-name>/ --profile pentest-temp | head -20

# 5. 清除临时 profile
aws configure --profile pentest-temp set aws_access_key_id ""
aws configure --profile pentest-temp set aws_secret_access_key ""
aws configure --profile pentest-temp set aws_session_token ""
# 或直接编辑 ~/.aws/credentials，删除 [pentest-temp] 节
```

## 结果解读

- `get-caller-identity` 有响应即说明凭据有效，`Account` 字段为账号 ID，`Arn` 包含用户/角色路径。
- `simulate-principal-policy` 返回每个 action 的 `EvalDecision`（allowed/implicitDeny/explicitDeny），可在不实际操作的情况下确认权限边界。
- S3 `ls` 返回 bucket 列表和根前缀条目，记录 bucket 数量及命名规律，不进入子目录、不下载文件。
