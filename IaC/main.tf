/* Configurando AWS ECR */
# Crear el repositorio en ECR
resource "aws_ecr_repository" "ecr" {
    name                 = var.ecr_repo
    image_tag_mutability = var.image_mutability
    encryption_configuration {
            encryption_type = var.encrypt_type
        }
    image_scanning_configuration {
            scan_on_push = true
        }
    tags = var.tags
}

/* Configurando AWS IAM */
# Creando usuario
resource "aws_iam_user" "iam_user" {
    name          = var.ci_name
    force_destroy = true
    tags = var.tags
}

# Creando group
resource "aws_iam_group" "iam_group" {
    name = var.ci_name
}

# Asignando IAM user a group
resource "aws_iam_group_membership" "main" {
    name  = "${var.ci_name}-ecr-access"
    users = [var.ci_name]
    group = aws_iam_group.iam_group.name
}

# Creando Policy de acceso restringido
data "aws_iam_policy_document" "def_policy" {
    statement {
        actions = [
            "ecr:GetAuthorizationToken",
        ]
        resources = ["*"]
    }

    statement {
        actions = [
            "ecr:BatchCheckLayerAvailability",
            "ecr:GetDownloadUrlForLayer",
            "ecr:GetRepositoryPolicy",
            "ecr:DescribeRepositories",
            "ecr:ListImages",
            "ecr:DescribeImages",
            "ecr:BatchGetImage",
            "ecr:InitiateLayerUpload",
            "ecr:UploadLayerPart",
            "ecr:CompleteLayerUpload",
            "ecr:PutImage",
        ]
    resources = [
            aws_ecr_repository.ecr.arn,
        ]
    }
}

resource "aws_iam_policy" "iam_ecr_policy" {
  name        = "${var.ci_name}-ecr-push-policy"
  description = "Allow ${var.ci_name} to push new ${var.ecr_repo} ECR images"
  path        = "/"
  policy      = data.aws_iam_policy_document.def_policy.json
}

# Asignando policy a group
resource "aws_iam_group_policy_attachment" "grant_access" {
  group      = aws_iam_group.iam_group.name
  policy_arn = aws_iam_policy.iam_ecr_policy.arn
}

# Creando access_key y access_secret para el usuario de CI
resource "aws_iam_access_key" "access_ecr" {
  user    = aws_iam_user.iam_user.name
  pgp_key = var.public_pgp_key
}

output "access_id" {
  value = aws_iam_access_key.access_ecr.id
}

output "access_secret" {
  value = aws_iam_access_key.access_ecr.encrypted_secret
}

/* Configurando AWS VPC */
# Obteniendo los AZ disponibles en la region de AWS
data "aws_availability_zones" "available" {}

# Creando VPC
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.1.0"

  name = var.vpc_name

  cidr = "10.0.0.0/16"
  azs  = slice(data.aws_availability_zones.available.names, 0, 3)

  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.4.0/24", "10.0.5.0/24", "10.0.6.0/24"]

  enable_nat_gateway   = true
  single_nat_gateway   = true
  enable_dns_hostnames = true

  public_subnet_tags = {
    "kubernetes.io/cluster/${var.cluster_name}" = "shared"
    "kubernetes.io/role/elb"                      = 1
  }

  private_subnet_tags = {
    "kubernetes.io/cluster/${var.cluster_name}" = "shared"
    "kubernetes.io/role/internal-elb"             = 1
  }
}

/* Creando Cluster en EKS */
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "19.15.4"

  cluster_name    = var.cluster_name
  cluster_version = "1.27"

  vpc_id                         = module.vpc.vpc_id
  subnet_ids                     = module.vpc.private_subnets
  cluster_endpoint_public_access = true

  eks_managed_node_group_defaults = {
    ami_type = "AL2_x86_64"

  }

  eks_managed_node_groups = {
    one = {
      name = "node-group-1"

      instance_types = ["t3a.small"]

      min_size     = 1
      max_size     = 2
      desired_size = 1
    }
  }
}

output "cluster_endpoint" {
  description = "Endpoint for EKS control plane"
  value       = module.eks.cluster_endpoint
}

output "cluster_name" {
  description = "Kubernetes Cluster Name"
  value       = module.eks.cluster_name
}

