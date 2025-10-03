# Hiraishin Framework - Terraform Main Configuration

terraform {
  required_version = ">= 1.6.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.24"
    }
  }
  
  # Remote state with locking
  backend "s3" {
    bucket         = "hiraishin-terraform-state"
    key            = "offensive-ops/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "hiraishin-terraform-locks"
  }
}

# ============================================================================
# Provider Configuration
# ============================================================================

provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Project     = "Ghost-Cyber-Universe"
      Component   = "Hiraishin-Framework"
      ManagedBy   = "Terraform"
      Environment = var.environment
    }
  }
}

# ============================================================================
# Variables
# ============================================================================

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "staging"
}

variable "cluster_name" {
  description = "Cluster name"
  type        = string
  default     = "red-team-ops"
}

variable "node_count" {
  description = "Number of nodes"
  type        = number
  default     = 3
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.medium"
}

variable "enable_snapshots" {
  description = "Enable automatic snapshots"
  type        = bool
  default     = true
}

# ============================================================================
# VPC Configuration
# ============================================================================

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  tags = {
    Name = "${var.cluster_name}-vpc"
  }
}

resource "aws_subnet" "public" {
  count                   = 3
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.${count.index + 1}.0/24"
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true
  
  tags = {
    Name = "${var.cluster_name}-public-subnet-${count.index + 1}"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  
  tags = {
    Name = "${var.cluster_name}-igw"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }
  
  tags = {
    Name = "${var.cluster_name}-public-rt"
  }
}

resource "aws_route_table_association" "public" {
  count          = 3
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# ============================================================================
# Security Group
# ============================================================================

resource "aws_security_group" "cluster" {
  name_prefix = "${var.cluster_name}-sg"
  vpc_id      = aws_vpc.main.id
  
  # SSH
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  # K3s API
  ingress {
    from_port   = 6443
    to_port     = 6443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  # HTTP/HTTPS
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
  
  # All outbound
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name = "${var.cluster_name}-sg"
  }
}

# ============================================================================
# EC2 Instances
# ============================================================================

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical
  
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
}

resource "aws_instance" "cluster_nodes" {
  count                  = var.node_count
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public[count.index % 3].id
  vpc_security_group_ids = [aws_security_group.cluster.id]
  key_name               = aws_key_pair.deployer.key_name
  
  user_data = templatefile("${path.module}/user-data.sh", {
    node_index = count.index
    cluster_name = var.cluster_name
  })
  
  root_block_device {
    volume_size = 50
    volume_type = "gp3"
    encrypted   = true
  }
  
  tags = {
    Name = "${var.cluster_name}-node-${count.index + 1}"
    Role = count.index == 0 ? "master" : "worker"
  }
}

resource "aws_key_pair" "deployer" {
  key_name   = "${var.cluster_name}-deployer"
  public_key = file("~/.ssh/id_rsa.pub")
}

# ============================================================================
# Snapshots
# ============================================================================

resource "aws_ebs_snapshot" "cluster_snapshots" {
  count       = var.enable_snapshots ? var.node_count : 0
  volume_id   = aws_instance.cluster_nodes[count.index].root_block_device[0].volume_id
  description = "Snapshot for ${var.cluster_name}-node-${count.index + 1}"
  
  tags = {
    Name = "${var.cluster_name}-snapshot-${count.index + 1}"
    Timestamp = timestamp()
  }
}

# ============================================================================
# Outputs
# ============================================================================

output "cluster_nodes_public_ips" {
  description = "Public IPs of cluster nodes"
  value       = aws_instance.cluster_nodes[*].public_ip
}

output "cluster_nodes_private_ips" {
  description = "Private IPs of cluster nodes"
  value       = aws_instance.cluster_nodes[*].private_ip
}

output "master_node_ip" {
  description = "Master node public IP"
  value       = aws_instance.cluster_nodes[0].public_ip
}

output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.main.id
}

output "security_group_id" {
  description = "Security group ID"
  value       = aws_security_group.cluster.id
}

# ============================================================================
# Data Sources
# ============================================================================

data "aws_availability_zones" "available" {
  state = "available"
}

# ============================================================================
# Performance Measurement
# ============================================================================

resource "time_static" "deploy_start" {}

resource "time_static" "deploy_end" {
  depends_on = [aws_instance.cluster_nodes]
}

output "deploy_duration_seconds" {
  description = "Deployment duration in seconds (target: < 180s)"
  value       = time_static.deploy_end.unix - time_static.deploy_start.unix
}
