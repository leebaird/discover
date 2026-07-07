terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.16"
    }
  }

  required_version = ">= 1.2.0"
}

provider "aws" {
  region = "us-east-1"
}

# ---------------------------------------------------------------------------------------------------------------------

resource "aws_instance" "redirector" {
  ami                    = "ami-052efd3df9dad4825" # Ubuntu for my region
  instance_type          = "t2.micro"
  key_name               = "deploy" # Created in AWS GUI
  vpc_security_group_ids = [aws_security_group.operators.id]

  tags = {
    Name = "Redirector"
  }

  provisioner "remote-exec" {
    connection {
      host        = aws_instance.redirector.public_ip
      type        = "ssh"
      user        = "ubuntu"
      agent       = true
      private_key = file("~/.ssh/deploy.pem")
    }

    inline = ["echo; echo '[*] Connected to new server.'; echo"]
  }

  provisioner "local-exec" {
    command = "ansible-playbook -u ubuntu -i '${aws_instance.redirector.public_ip},' --private-key ~/.ssh/deploy.pem ansible/redirector-c2.yml"
  }
}

# ---------------------------------------------------------------------------------------------------------------------

resource "aws_security_group" "operators" {
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["<operator IPs>"]
  }
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "Operators"
  }
}
