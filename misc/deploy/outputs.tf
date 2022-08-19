output "instance_id" {
  description = "ID of payload instance"
  value       = aws_instance.redirector.id
}

output "instance_ip" {
  description = "Public IP of the payload instance"
  value       = aws_instance.redirector.public_ip
}
