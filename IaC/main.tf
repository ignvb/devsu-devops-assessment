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
