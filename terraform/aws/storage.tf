###############################################################################
# S3. PLANTED ISSUES:
#  - Bucket has no server-side encryption configured
#  - Bucket has public-read ACL
#  - Versioning not enabled
#  - Access logging not configured
#  - No public access block resource
###############################################################################

resource "aws_s3_bucket" "data" {
  bucket = "${var.project_name}-data-${var.environment}"

  tags = var.tags
}

# PLANTED: public-read ACL.
resource "aws_s3_bucket_acl" "data" {
  bucket = aws_s3_bucket.data.id
  acl    = "public-read"
}

# PLANTED: versioning explicitly disabled.
resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    status = "Disabled"
  }
}

# PLANTED: no aws_s3_bucket_server_side_encryption_configuration resource.
# PLANTED: no aws_s3_bucket_logging resource.
# PLANTED: no aws_s3_bucket_public_access_block resource.
