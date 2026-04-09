###############################################################################
# RDS. PLANTED ISSUES:
#  - storage_encrypted = false
#  - publicly_accessible = true
#  - backup_retention_period = 0
#  - deletion_protection = false
#  - hardcoded password (via var.db_password default)
###############################################################################

resource "aws_db_subnet_group" "main" {
  name       = "${var.project_name}-db-subnets"
  subnet_ids = [aws_subnet.public_a.id, aws_subnet.public_b.id]
  tags       = var.tags
}

resource "aws_db_instance" "main" {
  identifier             = "${var.project_name}-db"
  engine                 = "postgres"
  engine_version         = "15.4"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  db_name                = "appdb"
  username               = var.db_username
  password               = var.db_password
  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.app.id]
  skip_final_snapshot    = true

  # PLANTED: not encrypted at rest.
  storage_encrypted = false

  # PLANTED: publicly accessible.
  publicly_accessible = true

  # PLANTED: zero-day backup retention.
  backup_retention_period = 0

  # PLANTED: deletion protection disabled.
  deletion_protection = false

  tags = var.tags
}
