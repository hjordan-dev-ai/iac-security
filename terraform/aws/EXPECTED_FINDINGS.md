# AWS Stack — Ground-Truth Planted Issues

20 manufactured misconfigurations seeded across the AWS mini-stack. The
`tools/ground_truth/compare.py` script matches scanner output against this
table to compute precision/recall.

| # | File | Resource | Category | Issue | Expected check IDs |
|---|---|---|---|---|---|
| 1 | main.tf | aws_vpc.main | logging | VPC has no flow logs | CKV2_AWS_11, CKV_AWS_50 |
| 2 | main.tf | aws_vpc.main | network | Default SG not restricted (no aws_default_security_group block) | CKV2_AWS_12 |
| 3 | compute.tf | aws_security_group.app | network | SSH (22) open to 0.0.0.0/0 | CKV_AWS_24, AVD-AWS-0107 |
| 4 | compute.tf | aws_security_group.app | network | RDP (3389) open to 0.0.0.0/0 | CKV_AWS_25, AVD-AWS-0107 |
| 5 | compute.tf | aws_instance.app | metadata | IMDSv1 still allowed (http_tokens != "required") | CKV_AWS_79, AVD-AWS-0028 |
| 6 | compute.tf | aws_instance.app | encryption | Root EBS volume not encrypted | CKV_AWS_8, AVD-AWS-0131 |
| 7 | compute.tf | aws_instance.app | logging | Detailed monitoring disabled | CKV_AWS_126 |
| 8 | storage.tf | aws_s3_bucket.data | encryption | S3 bucket no SSE configured | CKV_AWS_19, CKV2_AWS_67 |
| 9 | storage.tf | aws_s3_bucket_acl.data | exposure | Public-read ACL on S3 bucket | CKV_AWS_20, CKV_AWS_57 |
| 10 | storage.tf | aws_s3_bucket_versioning.data | governance | Versioning explicitly disabled | CKV_AWS_21 |
| 11 | storage.tf | aws_s3_bucket.data | logging | No access logging | CKV_AWS_18 |
| 12 | storage.tf | aws_s3_bucket.data | exposure | No public access block | CKV2_AWS_6 |
| 13 | iam.tf | aws_iam_role_policy.app_admin | iam | Wildcard `*:*` policy | CKV_AWS_62, CKV_AWS_286, CKV_AWS_290 |
| 14 | iam.tf | aws_iam_user.deploy | iam | IAM user with no MFA enforced | CKV_AWS_148 |
| 15 | iam.tf | (account) | iam | No password policy resource | CKV_AWS_9, CKV_AWS_10, CKV_AWS_11 |
| 16 | rds.tf | aws_db_instance.main | encryption | RDS storage_encrypted = false | CKV_AWS_16, AVD-AWS-0080 |
| 17 | rds.tf | aws_db_instance.main | exposure | RDS publicly_accessible = true | CKV_AWS_17, AVD-AWS-0082 |
| 18 | rds.tf | aws_db_instance.main | backup | backup_retention_period = 0 | CKV_AWS_133 |
| 19 | rds.tf | aws_db_instance.main | governance | deletion_protection = false | CKV_AWS_293 |
| 20 | variables.tf | var.db_password | secret | Hardcoded password as variable default | CKV_SECRET_6 |

## Tfvars repro

`variables.tf` declares `environment` and `allowed_ssh_cidrs` with no default,
and `terraform.tfvars` does not provide values for them. Some scanner
configurations also reference a non-existent `extra.tfvars`. This is the exact
condition that crashes the bundled Trivy in our current c7n-left toolchain.

The bake-off grades each scanner on three outcomes:

1. **Crash** (worst — current state with old Trivy)
2. **Skip silently with no error** (acceptable but loses coverage)
3. **Warn and continue scanning** (best — what we want from the replacement)
