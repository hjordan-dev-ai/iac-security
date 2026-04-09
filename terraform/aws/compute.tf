###############################################################################
# EC2 + SG. PLANTED ISSUES:
#  - SG allows 0.0.0.0/0 on port 22 (SSH from anywhere)
#  - SG allows 0.0.0.0/0 on port 3389 (RDP from anywhere)
#  - EC2 allows IMDSv1 (no http_tokens = "required")
#  - Root EBS volume not encrypted
#  - Detailed monitoring disabled
###############################################################################

resource "aws_security_group" "app" {
  name        = "${var.project_name}-app-sg"
  description = "App tier security group"
  vpc_id      = aws_vpc.main.id

  # PLANTED: SSH open to the world.
  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # PLANTED: RDP open to the world.
  ingress {
    description = "RDP"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = var.tags
}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
}

resource "aws_instance" "app" {
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = "t3.small"
  subnet_id                   = aws_subnet.public_a.id
  vpc_security_group_ids      = [aws_security_group.app.id]
  associate_public_ip_address = true

  # PLANTED: detailed monitoring disabled.
  monitoring = false

  # PLANTED: IMDSv1 still allowed (no http_tokens = "required" enforcement).
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"
  }

  # PLANTED: root volume not encrypted.
  root_block_device {
    volume_size = 20
    volume_type = "gp3"
    encrypted   = false
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-app-${var.environment}"
  })
}
