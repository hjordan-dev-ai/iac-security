###############################################################################
# IAM. PLANTED ISSUES:
#  - Inline policy with Action "*" Resource "*"
#  - IAM user with no MFA enforced
#  - Account password policy missing entirely
###############################################################################

resource "aws_iam_role" "app" {
  name = "${var.project_name}-app-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = var.tags
}

# PLANTED: full admin wildcard policy.
resource "aws_iam_role_policy" "app_admin" {
  name = "${var.project_name}-app-admin"
  role = aws_iam_role.app.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

# PLANTED: IAM user with no MFA. No aws_iam_user_policy attaching an MFA
# enforcement condition exists.
resource "aws_iam_user" "deploy" {
  name = "${var.project_name}-deploy"
  tags = var.tags
}

resource "aws_iam_access_key" "deploy" {
  user = aws_iam_user.deploy.name
}

# PLANTED: no aws_iam_account_password_policy resource.
