resource "aws_db_subnet_group" "this" {
  name       = "toolgate"
  subnet_ids = var.private_subnet_ids
}

# The master password is generated and rotated by RDS into a Secrets Manager
# secret (manage_master_user_password); Terraform never sees it.
resource "aws_db_instance" "this" {
  identifier                  = "toolgate"
  engine                      = "postgres"
  engine_version              = "16"
  instance_class              = "db.t4g.micro"
  storage_type                = "gp3"
  allocated_storage           = 20
  db_name                     = "toolgate"
  username                    = "toolgate"
  manage_master_user_password = true
  db_subnet_group_name        = aws_db_subnet_group.this.name
  vpc_security_group_ids      = [var.db_sg_id]
  publicly_accessible         = false
  storage_encrypted           = true
  multi_az                    = false
  backup_retention_period     = 1
  skip_final_snapshot         = true
  deletion_protection         = false
}
