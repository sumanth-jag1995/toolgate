output "vpc_id" {
  value = aws_vpc.this.id
}

output "public_subnet_ids" {
  value = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  value = aws_subnet.private[*].id
}

output "alb_sg_id" {
  value = aws_security_group.alb.id
}

output "service_sg_id" {
  value = aws_security_group.service.id
}

output "db_sg_id" {
  value = aws_security_group.db.id
}
