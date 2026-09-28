# Small dedicated VPC with two public subnets.
# No NAT gateway or load balancer keeps the lab close to free: tasks get a public IP and
# the security group restricts who can reach them. A dedicated NACL lets the automated
# responder add explicit DENY rules for attacking IPs.

data "aws_caller_identity" "current" {}

data "aws_availability_zones" "available" {
  # checkov:skip=CKV_AWS_394:Only the first two zones are used; a newly added zone does not change the subnets in this lab
  state = "available"
  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"] # skip Local/Wavelength zones that need opt-in
  }
}

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "${var.name}-vpc" }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.name}-igw" }
}

resource "aws_subnet" "public" {
  # checkov:skip=CKV_AWS_130:Public IPs are required because this lab avoids a paid NAT gateway/load balancer
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(aws_vpc.main.cidr_block, 8, count.index)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true
  tags                    = { Name = "${var.name}-public-${count.index}" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }
  tags = { Name = "${var.name}-public" }
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# Lock down the VPC's default security group so nothing uses it by accident.
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.name}-default-locked" }
}

resource "aws_security_group" "api" {
  # checkov:skip=CKV2_AWS_5:Attached to the ECS service in the app_service module (wired in root main.tf; the scanner does not follow cross-module links)
  name        = "${var.name}-api"
  description = "Allow HTTP to the API container from approved CIDRs only"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "API port from allowed CIDRs"
    from_port   = var.app_port
    to_port     = var.app_port
    protocol    = "tcp"
    cidr_blocks = var.allowed_ingress_cidrs
  }

  egress {
    description = "HTTPS out (ECR image pulls, CloudWatch Logs, Secrets Manager)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.name}-api" }
}

# --- Network ACL used for automated deny-listing ---
# Allow rules are separate resources so the responder's deny rules (1-90) survive `terraform apply`.
resource "aws_network_acl" "public" {
  # checkov:skip=CKV2_AWS_1:Attached to both public subnets via subnet_ids (scanner does not resolve the splat expression)
  vpc_id     = aws_vpc.main.id
  subnet_ids = aws_subnet.public[*].id
  tags       = { Name = "${var.name}-public-nacl" }
}

resource "aws_network_acl_rule" "ingress_allow_all" {
  # checkov:skip=CKV_AWS_229:Allow-all baseline; the security group restricts ports/sources. This NACL exists for deny-listing
  # checkov:skip=CKV_AWS_230:Allow-all baseline; the security group restricts ports/sources. This NACL exists for deny-listing
  # checkov:skip=CKV_AWS_231:Allow-all baseline; the security group restricts ports/sources. This NACL exists for deny-listing
  # checkov:skip=CKV_AWS_232:Allow-all baseline; the security group restricts ports/sources. This NACL exists for deny-listing
  # checkov:skip=CKV_AWS_352:Allow-all baseline; the security group restricts ports/sources. This NACL exists for deny-listing
  network_acl_id = aws_network_acl.public.id
  rule_number    = 100
  egress         = false
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}

resource "aws_network_acl_rule" "egress_allow_all" {
  network_acl_id = aws_network_acl.public.id
  rule_number    = 100
  egress         = true
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}

# --- VPC Flow Logs: network-level telemetry for investigations ---
resource "aws_cloudwatch_log_group" "flow_logs" {
  # checkov:skip=CKV_AWS_338:Retention kept short to minimise cost in a lab environment
  name              = "/vpc/${var.name}/flow-logs"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
}

resource "aws_flow_log" "main" {
  vpc_id          = aws_vpc.main.id
  traffic_type    = "ALL"
  log_destination = aws_cloudwatch_log_group.flow_logs.arn
  iam_role_arn    = aws_iam_role.flow_logs.arn
}

data "aws_iam_policy_document" "flow_logs_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_iam_role" "flow_logs" {
  name               = "${var.name}-flow-logs"
  assume_role_policy = data.aws_iam_policy_document.flow_logs_assume.json
}

data "aws_iam_policy_document" "flow_logs" {
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
    resources = ["${aws_cloudwatch_log_group.flow_logs.arn}:*"]
  }
}

resource "aws_iam_role_policy" "flow_logs" {
  name   = "write-flow-logs"
  role   = aws_iam_role.flow_logs.id
  policy = data.aws_iam_policy_document.flow_logs.json
}
