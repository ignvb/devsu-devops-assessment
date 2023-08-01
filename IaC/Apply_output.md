# Terraform apply

El siguiente es la salida obtenida al ejecutar ```terraform apply```

```log
module.eks.module.eks_managed_node_group["one"].data.aws_partition.current: Reading...
module.eks.data.aws_caller_identity.current: Reading...
module.lb_role.data.aws_partition.current: Reading...
module.eks.module.kms.data.aws_partition.current: Reading...
module.eks.module.eks_managed_node_group["one"].data.aws_caller_identity.current: Reading...
module.eks.data.aws_partition.current: Reading...
module.lb_role.data.aws_caller_identity.current: Reading...
module.eks.data.aws_partition.current: Read complete after 0s [id=aws]
module.lb_role.data.aws_region.current: Reading...
module.lb_role.data.aws_partition.current: Read complete after 0s [id=aws]
module.eks.module.kms.data.aws_partition.current: Read complete after 0s [id=aws]
module.eks.module.eks_managed_node_group["one"].data.aws_partition.current: Read complete after 0s [id=aws]
module.eks.module.kms.data.aws_caller_identity.current: Reading...
data.aws_availability_zones.available: Reading...
aws_ecr_repository.ecr: Refreshing state... [id=devsu-demo]
module.lb_role.data.aws_region.current: Read complete after 0s [id=us-east-1]
module.eks.module.eks_managed_node_group["one"].data.aws_iam_policy_document.assume_role_policy[0]: Reading...
module.eks.module.eks_managed_node_group["one"].data.aws_iam_policy_document.assume_role_policy[0]: Read complete after 0s [id=2560088296]
module.eks.data.aws_iam_policy_document.assume_role_policy[0]: Reading...
module.lb_role.data.aws_iam_policy_document.load_balancer_controller[0]: Reading...
module.eks.data.aws_iam_policy_document.assume_role_policy[0]: Read complete after 0s [id=2764486067]
module.lb_role.data.aws_iam_policy_document.load_balancer_controller[0]: Read complete after 0s [id=3014472196]
module.lb_role.data.aws_caller_identity.current: Read complete after 0s [id=951903200613]
module.eks.module.kms.data.aws_caller_identity.current: Read complete after 0s [id=951903200613]
module.eks.module.eks_managed_node_group["one"].data.aws_caller_identity.current: Read complete after 0s [id=951903200613]
module.eks.data.aws_caller_identity.current: Read complete after 0s [id=951903200613]
module.eks.data.aws_iam_session_context.current: Reading...
module.eks.data.aws_iam_session_context.current: Read complete after 0s [id=arn:aws:iam::951903200613:user/Admin]
data.aws_iam_policy_document.def_policy: Reading...
data.aws_iam_policy_document.def_policy: Read complete after 0s [id=2593946032]
data.aws_availability_zones.available: Read complete after 1s [id=us-east-1]

Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the
following symbols:
  + create
 <= read (data resources)

Terraform will perform the following actions:

  # aws_iam_access_key.access_ecr will be created
  + resource "aws_iam_access_key" "access_ecr" {
      + create_date                    = (known after apply)
      + encrypted_secret               = (known after apply)
      + encrypted_ses_smtp_password_v4 = (known after apply)
      + id                             = (known after apply)
      + key_fingerprint                = (known after apply)
      + pgp_key                        = (sensitive value)
      + secret                         = (sensitive value)
      + ses_smtp_password_v4           = (sensitive value)
      + status                         = "Active"
      + user                           = "gh_action"
    }

  # aws_iam_group.iam_group will be created
  + resource "aws_iam_group" "iam_group" {
      + arn       = (known after apply)
      + id        = (known after apply)
      + name      = "gh_action"
      + path      = "/"
      + unique_id = (known after apply)
    }

  # aws_iam_group_membership.main will be created
  + resource "aws_iam_group_membership" "main" {
      + group = "gh_action"
      + id    = (known after apply)
      + name  = "gh_action-ecr-access"
      + users = [
          + "gh_action",
        ]
    }

  # aws_iam_group_policy_attachment.grant_access will be created
  + resource "aws_iam_group_policy_attachment" "grant_access" {
      + group      = "gh_action"
      + id         = (known after apply)
      + policy_arn = (known after apply)
    }

  # aws_iam_policy.iam_ecr_policy will be created
  + resource "aws_iam_policy" "iam_ecr_policy" {
      + arn         = (known after apply)
      + description = "Allow gh_action to push new devsu-demo ECR images"
      + id          = (known after apply)
      + name        = "gh_action-ecr-push-policy"
      + name_prefix = (known after apply)
      + path        = "/"
      + policy      = jsonencode(
            {
              + Statement = [
                  + {
                      + Action   = "ecr:GetAuthorizationToken"
                      + Effect   = "Allow"
                      + Resource = "*"
                    },
                  + {
                      + Action   = [
                          + "ecr:UploadLayerPart",
                          + "ecr:PutImage",
                          + "ecr:ListImages",
                          + "ecr:InitiateLayerUpload",
                          + "ecr:GetRepositoryPolicy",
                          + "ecr:GetDownloadUrlForLayer",
                          + "ecr:DescribeRepositories",
                          + "ecr:DescribeImages",
                          + "ecr:CompleteLayerUpload",
                          + "ecr:BatchGetImage",
                          + "ecr:BatchCheckLayerAvailability",
                        ]
                      + Effect   = "Allow"
                      + Resource = "arn:aws:ecr:us-east-1:951903200613:repository/devsu-demo"
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + policy_id   = (known after apply)
      + tags_all    = (known after apply)
    }

  # aws_iam_user.iam_user will be created
  + resource "aws_iam_user" "iam_user" {
      + arn           = (known after apply)
      + force_destroy = true
      + id            = (known after apply)
      + name          = "gh_action"
      + path          = "/"
      + tags          = {
          + "Automation" = "Terraform"
          + "Project"    = "Devsu-demo"
        }
      + tags_all      = {
          + "Automation" = "Terraform"
          + "Project"    = "Devsu-demo"
        }
      + unique_id     = (known after apply)
    }

  # helm_release.lb will be created
  + resource "helm_release" "lb" {
      + atomic                     = false
      + chart                      = "aws-load-balancer-controller"
      + cleanup_on_fail            = false
      + create_namespace           = false
      + dependency_update          = false
      + disable_crd_hooks          = false
      + disable_openapi_validation = false
      + disable_webhooks           = false
      + force_update               = false
      + id                         = (known after apply)
      + lint                       = false
      + manifest                   = (known after apply)
      + max_history                = 0
      + metadata                   = (known after apply)
      + name                       = "aws-load-balancer-controller"
      + namespace                  = "kube-system"
      + pass_credentials           = false
      + recreate_pods              = false
      + render_subchart_notes      = true
      + replace                    = false
      + repository                 = "https://aws.github.io/eks-charts"
      + reset_values               = false
      + reuse_values               = false
      + skip_crds                  = false
      + status                     = "deployed"
      + timeout                    = 300
      + verify                     = false
      + version                    = "1.5.5"
      + wait                       = true
      + wait_for_jobs              = false

      + set {
          + name  = "clusterName"
          + value = "k8s-devsu-demo"
        }
      + set {
          + name  = "image.repository"
          + value = "602401143452.dkr.ecr.us-east-1.amazonaws.com/amazon/aws-load-balancer-controller"
        }
      + set {
          + name  = "region"
          + value = "us-east-1"
        }
      + set {
          + name  = "serviceAccount.create"
          + value = "false"
        }
      + set {
          + name  = "serviceAccount.name"
          + value = "aws-load-balancer-controller"
        }
      + set {
          + name  = "vpcId"
          + value = (known after apply)
        }
    }

  # helm_release.metrics_server will be created
  + resource "helm_release" "metrics_server" {
      + atomic                     = false
      + chart                      = "metrics-server"
      + cleanup_on_fail            = false
      + create_namespace           = false
      + dependency_update          = false
      + disable_crd_hooks          = false
      + disable_openapi_validation = false
      + disable_webhooks           = false
      + force_update               = false
      + id                         = (known after apply)
      + lint                       = false
      + manifest                   = (known after apply)
      + max_history                = 0
      + metadata                   = (known after apply)
      + name                       = "metrics-server"
      + namespace                  = "kube-system"
      + pass_credentials           = false
      + recreate_pods              = false
      + render_subchart_notes      = true
      + replace                    = false
      + repository                 = "https://kubernetes-sigs.github.io/metrics-server/"
      + reset_values               = false
      + reuse_values               = false
      + skip_crds                  = false
      + status                     = "deployed"
      + timeout                    = 300
      + verify                     = false
      + version                    = "3.10.0"
      + wait                       = true
      + wait_for_jobs              = false
    }

  # helm_release.sealed-secrets will be created
  + resource "helm_release" "sealed-secrets" {
      + atomic                     = false
      + chart                      = "sealed-secrets"
      + cleanup_on_fail            = false
      + create_namespace           = false
      + dependency_update          = false
      + disable_crd_hooks          = false
      + disable_openapi_validation = false
      + disable_webhooks           = false
      + force_update               = false
      + id                         = (known after apply)
      + lint                       = false
      + manifest                   = (known after apply)
      + max_history                = 0
      + metadata                   = (known after apply)
      + name                       = "sealed-secrets"
      + namespace                  = "sealed-secrets"
      + pass_credentials           = false
      + recreate_pods              = false
      + render_subchart_notes      = true
      + replace                    = false
      + repository                 = "https://bitnami-labs.github.io/sealed-secrets"
      + reset_values               = false
      + reuse_values               = false
      + skip_crds                  = false
      + status                     = "deployed"
      + timeout                    = 300
      + verify                     = false
      + version                    = "2.11.0"
      + wait                       = true
      + wait_for_jobs              = false
    }

  # kubernetes_namespace.prod-ns will be created
  + resource "kubernetes_namespace" "prod-ns" {
      + id                               = (known after apply)
      + wait_for_default_service_account = false

      + metadata {
          + generation       = (known after apply)
          + name             = "prod"
          + resource_version = (known after apply)
          + uid              = (known after apply)
        }
    }

  # kubernetes_namespace.sealed-secrets-ns will be created
  + resource "kubernetes_namespace" "sealed-secrets-ns" {
      + id                               = (known after apply)
      + wait_for_default_service_account = false

      + metadata {
          + generation       = (known after apply)
          + name             = "sealed-secrets"
          + resource_version = (known after apply)
          + uid              = (known after apply)
        }
    }

  # kubernetes_secret.sealed-secrets-key will be created
  + resource "kubernetes_secret" "sealed-secrets-key" {
      + data                           = (sensitive value)
      + id                             = (known after apply)
      + type                           = "kubernetes.io/tls"
      + wait_for_service_account_token = true

      + metadata {
          + generation       = (known after apply)
          + labels           = {
              + "sealedsecrets.bitnami.com/sealed-secrets-key" = "active"
            }
          + name             = "sealed-secrets-key"
          + namespace        = "sealed-secrets"
          + resource_version = (known after apply)
          + uid              = (known after apply)
        }
    }

  # kubernetes_service_account.service-account will be created
  + resource "kubernetes_service_account" "service-account" {
      + automount_service_account_token = true
      + default_secret_name             = (known after apply)
      + id                              = (known after apply)

      + metadata {
          + annotations      = (known after apply)
          + generation       = (known after apply)
          + labels           = {
              + "app.kubernetes.io/component" = "controller"
              + "app.kubernetes.io/name"      = "aws-load-balancer-controller"
            }
          + name             = "aws-load-balancer-controller"
          + namespace        = "kube-system"
          + resource_version = (known after apply)
          + uid              = (known after apply)
        }
    }

  # module.eks.data.tls_certificate.this[0] will be read during apply
  # (config refers to values not yet known)
 <= data "tls_certificate" "this" {
      + certificates = (known after apply)
      + id           = (known after apply)
      + url          = (known after apply)
    }

  # module.eks.aws_cloudwatch_log_group.this[0] will be created
  + resource "aws_cloudwatch_log_group" "this" {
      + arn               = (known after apply)
      + id                = (known after apply)
      + name              = "/aws/eks/k8s-devsu-demo/cluster"
      + name_prefix       = (known after apply)
      + retention_in_days = 90
      + skip_destroy      = false
      + tags              = {
          + "Name" = "/aws/eks/k8s-devsu-demo/cluster"
        }
      + tags_all          = {
          + "Name" = "/aws/eks/k8s-devsu-demo/cluster"
        }
    }

  # module.eks.aws_eks_cluster.this[0] will be created
  + resource "aws_eks_cluster" "this" {
      + arn                       = (known after apply)
      + certificate_authority     = (known after apply)
      + cluster_id                = (known after apply)
      + created_at                = (known after apply)
      + enabled_cluster_log_types = [
          + "api",
          + "audit",
          + "authenticator",
        ]
      + endpoint                  = (known after apply)
      + id                        = (known after apply)
      + identity                  = (known after apply)
      + name                      = "k8s-devsu-demo"
      + platform_version          = (known after apply)
      + role_arn                  = (known after apply)
      + status                    = (known after apply)
      + tags_all                  = (known after apply)
      + version                   = "1.27"

      + encryption_config {
          + resources = [
              + "secrets",
            ]

          + provider {
              + key_arn = (known after apply)
            }
        }

      + kubernetes_network_config {
          + ip_family         = (known after apply)
          + service_ipv4_cidr = (known after apply)
          + service_ipv6_cidr = (known after apply)
        }

      + timeouts {}

      + vpc_config {
          + cluster_security_group_id = (known after apply)
          + endpoint_private_access   = true
          + endpoint_public_access    = true
          + public_access_cidrs       = [
              + "0.0.0.0/0",
            ]
          + security_group_ids        = (known after apply)
          + subnet_ids                = (known after apply)
          + vpc_id                    = (known after apply)
        }
    }

  # module.eks.aws_iam_openid_connect_provider.oidc_provider[0] will be created
  + resource "aws_iam_openid_connect_provider" "oidc_provider" {
      + arn             = (known after apply)
      + client_id_list  = [
          + "sts.amazonaws.com",
        ]
      + id              = (known after apply)
      + tags            = {
          + "Name" = "k8s-devsu-demo-eks-irsa"
        }
      + tags_all        = {
          + "Name" = "k8s-devsu-demo-eks-irsa"
        }
      + thumbprint_list = (known after apply)
      + url             = (known after apply)
    }

  # module.eks.aws_iam_policy.cluster_encryption[0] will be created
  + resource "aws_iam_policy" "cluster_encryption" {
      + arn         = (known after apply)
      + description = "Cluster encryption policy to allow cluster role to utilize CMK provided"
      + id          = (known after apply)
      + name        = (known after apply)
      + name_prefix = "k8s-devsu-demo-cluster-ClusterEncryption"
      + path        = "/"
      + policy      = (known after apply)
      + policy_id   = (known after apply)
      + tags_all    = (known after apply)
    }

  # module.eks.aws_iam_role.this[0] will be created
  + resource "aws_iam_role" "this" {
      + arn                   = (known after apply)
      + assume_role_policy    = jsonencode(
            {
              + Statement = [
                  + {
                      + Action    = "sts:AssumeRole"
                      + Effect    = "Allow"
                      + Principal = {
                          + Service = "eks.amazonaws.com"
                        }
                      + Sid       = "EKSClusterAssumeRole"
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + create_date           = (known after apply)
      + force_detach_policies = true
      + id                    = (known after apply)
      + managed_policy_arns   = (known after apply)
      + max_session_duration  = 3600
      + name                  = (known after apply)
      + name_prefix           = "k8s-devsu-demo-cluster-"
      + path                  = "/"
      + tags_all              = (known after apply)
      + unique_id             = (known after apply)

      + inline_policy {
          + name   = "k8s-devsu-demo-cluster"
          + policy = jsonencode(
                {
                  + Statement = [
                      + {
                          + Action   = [
                              + "logs:CreateLogGroup",
                            ]
                          + Effect   = "Deny"
                          + Resource = "*"
                        },
                    ]
                  + Version   = "2012-10-17"
                }
            )
        }
    }

  # module.eks.aws_iam_role_policy_attachment.cluster_encryption[0] will be created
  + resource "aws_iam_role_policy_attachment" "cluster_encryption" {
      + id         = (known after apply)
      + policy_arn = (known after apply)
      + role       = (known after apply)
    }

  # module.eks.aws_iam_role_policy_attachment.this["AmazonEKSClusterPolicy"] will be created
  + resource "aws_iam_role_policy_attachment" "this" {
      + id         = (known after apply)
      + policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
      + role       = (known after apply)
    }

  # module.eks.aws_iam_role_policy_attachment.this["AmazonEKSVPCResourceController"] will be created
  + resource "aws_iam_role_policy_attachment" "this" {
      + id         = (known after apply)
      + policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
      + role       = (known after apply)
    }

  # module.eks.aws_security_group.cluster[0] will be created
  + resource "aws_security_group" "cluster" {
      + arn                    = (known after apply)
      + description            = "EKS cluster security group"
      + egress                 = (known after apply)
      + id                     = (known after apply)
      + ingress                = (known after apply)
      + name                   = (known after apply)
      + name_prefix            = "k8s-devsu-demo-cluster-"
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = {
          + "Name" = "k8s-devsu-demo-cluster"
        }
      + tags_all               = {
          + "Name" = "k8s-devsu-demo-cluster"
        }
      + vpc_id                 = (known after apply)
    }

  # module.eks.aws_security_group.node[0] will be created
  + resource "aws_security_group" "node" {
      + arn                    = (known after apply)
      + description            = "EKS node shared security group"
      + egress                 = (known after apply)
      + id                     = (known after apply)
      + ingress                = (known after apply)
      + name                   = (known after apply)
      + name_prefix            = "k8s-devsu-demo-node-"
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = {
          + "Name"                                 = "k8s-devsu-demo-node"
          + "kubernetes.io/cluster/k8s-devsu-demo" = "owned"
        }
      + tags_all               = {
          + "Name"                                 = "k8s-devsu-demo-node"
          + "kubernetes.io/cluster/k8s-devsu-demo" = "owned"
        }
      + vpc_id                 = (known after apply)
    }

  # module.eks.aws_security_group_rule.cluster["ingress_nodes_443"] will be created
  + resource "aws_security_group_rule" "cluster" {
      + description              = "Node groups to cluster API"
      + from_port                = 443
      + id                       = (known after apply)
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + security_group_rule_id   = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 443
      + type                     = "ingress"
    }

  # module.eks.aws_security_group_rule.node["egress_all"] will be created
  + resource "aws_security_group_rule" "node" {
      + cidr_blocks              = [
          + "0.0.0.0/0",
        ]
      + description              = "Allow all egress"
      + from_port                = 0
      + id                       = (known after apply)
      + prefix_list_ids          = []
      + protocol                 = "-1"
      + security_group_id        = (known after apply)
      + security_group_rule_id   = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 0
      + type                     = "egress"
    }

  # module.eks.aws_security_group_rule.node["ingress_cluster_443"] will be created
  + resource "aws_security_group_rule" "node" {
      + description              = "Cluster API to node groups"
      + from_port                = 443
      + id                       = (known after apply)
      + prefix_list_ids          = []
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + security_group_rule_id   = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 443
      + type                     = "ingress"
    }

  # module.eks.aws_security_group_rule.node["ingress_cluster_4443_webhook"] will be created
  + resource "aws_security_group_rule" "node" {
      + description              = "Cluster API to node 4443/tcp webhook"
      + from_port                = 4443
      + id                       = (known after apply)
      + prefix_list_ids          = []
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + security_group_rule_id   = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 4443
      + type                     = "ingress"
    }

  # module.eks.aws_security_group_rule.node["ingress_cluster_6443_webhook"] will be created
  + resource "aws_security_group_rule" "node" {
      + description              = "Cluster API to node 6443/tcp webhook"
      + from_port                = 6443
      + id                       = (known after apply)
      + prefix_list_ids          = []
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + security_group_rule_id   = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 6443
      + type                     = "ingress"
    }

  # module.eks.aws_security_group_rule.node["ingress_cluster_8443_webhook"] will be created
  + resource "aws_security_group_rule" "node" {
      + description              = "Cluster API to node 8443/tcp webhook"
      + from_port                = 8443
      + id                       = (known after apply)
      + prefix_list_ids          = []
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + security_group_rule_id   = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 8443
      + type                     = "ingress"
    }

  # module.eks.aws_security_group_rule.node["ingress_cluster_9443_webhook"] will be created
  + resource "aws_security_group_rule" "node" {
      + description              = "Cluster API to node 9443/tcp webhook"
      + from_port                = 9443
      + id                       = (known after apply)
      + prefix_list_ids          = []
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + security_group_rule_id   = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 9443
      + type                     = "ingress"
    }

  # module.eks.aws_security_group_rule.node["ingress_cluster_kubelet"] will be created
  + resource "aws_security_group_rule" "node" {
      + description              = "Cluster API to node kubelets"
      + from_port                = 10250
      + id                       = (known after apply)
      + prefix_list_ids          = []
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + security_group_rule_id   = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 10250
      + type                     = "ingress"
    }

  # module.eks.aws_security_group_rule.node["ingress_nodes_ephemeral"] will be created
  + resource "aws_security_group_rule" "node" {
      + description              = "Node to node ingress on ephemeral ports"
      + from_port                = 1025
      + id                       = (known after apply)
      + prefix_list_ids          = []
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + security_group_rule_id   = (known after apply)
      + self                     = true
      + source_security_group_id = (known after apply)
      + to_port                  = 65535
      + type                     = "ingress"
    }

  # module.eks.aws_security_group_rule.node["ingress_self_coredns_tcp"] will be created
  + resource "aws_security_group_rule" "node" {
      + description              = "Node to node CoreDNS"
      + from_port                = 53
      + id                       = (known after apply)
      + prefix_list_ids          = []
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + security_group_rule_id   = (known after apply)
      + self                     = true
      + source_security_group_id = (known after apply)
      + to_port                  = 53
      + type                     = "ingress"
    }

  # module.eks.aws_security_group_rule.node["ingress_self_coredns_udp"] will be created
  + resource "aws_security_group_rule" "node" {
      + description              = "Node to node CoreDNS UDP"
      + from_port                = 53
      + id                       = (known after apply)
      + prefix_list_ids          = []
      + protocol                 = "udp"
      + security_group_id        = (known after apply)
      + security_group_rule_id   = (known after apply)
      + self                     = true
      + source_security_group_id = (known after apply)
      + to_port                  = 53
      + type                     = "ingress"
    }

  # module.eks.time_sleep.this[0] will be created
  + resource "time_sleep" "this" {
      + create_duration = "30s"
      + id              = (known after apply)
      + triggers        = {
          + "cluster_certificate_authority_data" = (known after apply)
          + "cluster_endpoint"                   = (known after apply)
          + "cluster_name"                       = "k8s-devsu-demo"
          + "cluster_version"                    = "1.27"
        }
    }

  # module.lb_role.data.aws_iam_policy_document.this[0] will be read during apply
  # (config refers to values not yet known)
 <= data "aws_iam_policy_document" "this" {
      + id   = (known after apply)
      + json = (known after apply)

      + statement {
          + actions = [
              + "sts:AssumeRoleWithWebIdentity",
            ]
          + effect  = "Allow"

          + condition {
              + test     = "StringEquals"
              + values   = [
                  + "sts.amazonaws.com",
                ]
              + variable = (known after apply)
            }
          + condition {
              + test     = "StringEquals"
              + values   = [
                  + "system:serviceaccount:kube-system:aws-load-balancer-controller",
                ]
              + variable = (known after apply)
            }

          + principals {
              + identifiers = [
                  + (known after apply),
                ]
              + type        = "Federated"
            }
        }
    }

  # module.lb_role.aws_iam_policy.load_balancer_controller[0] will be created
  + resource "aws_iam_policy" "load_balancer_controller" {
      + arn         = (known after apply)
      + description = "Provides permissions for AWS Load Balancer Controller addon"
      + id          = (known after apply)
      + name        = (known after apply)
      + name_prefix = "AmazonEKS_AWS_Load_Balancer_Controller-"
      + path        = "/"
      + policy      = jsonencode(
            {
              + Statement = [
                  + {
                      + Action    = "iam:CreateServiceLinkedRole"
                      + Condition = {
                          + StringEquals = {
                              + "iam:AWSServiceName" = "elasticloadbalancing.amazonaws.com"
                            }
                        }
                      + Effect    = "Allow"
                      + Resource  = "*"
                    },
                  + {
                      + Action   = [
                          + "elasticloadbalancing:DescribeTargetHealth",
                          + "elasticloadbalancing:DescribeTargetGroups",
                          + "elasticloadbalancing:DescribeTargetGroupAttributes",
                          + "elasticloadbalancing:DescribeTags",
                          + "elasticloadbalancing:DescribeSSLPolicies",
                          + "elasticloadbalancing:DescribeRules",
                          + "elasticloadbalancing:DescribeLoadBalancers",
                          + "elasticloadbalancing:DescribeLoadBalancerAttributes",
                          + "elasticloadbalancing:DescribeListeners",
                          + "elasticloadbalancing:DescribeListenerCertificates",
                          + "ec2:GetCoipPoolUsage",
                          + "ec2:DescribeVpcs",
                          + "ec2:DescribeVpcPeeringConnections",
                          + "ec2:DescribeTags",
                          + "ec2:DescribeSubnets",
                          + "ec2:DescribeSecurityGroups",
                          + "ec2:DescribeNetworkInterfaces",
                          + "ec2:DescribeInternetGateways",
                          + "ec2:DescribeInstances",
                          + "ec2:DescribeCoipPools",
                          + "ec2:DescribeAvailabilityZones",
                          + "ec2:DescribeAddresses",
                          + "ec2:DescribeAccountAttributes",
                        ]
                      + Effect   = "Allow"
                      + Resource = "*"
                    },
                  + {
                      + Action   = [
                          + "wafv2:GetWebACLForResource",
                          + "wafv2:GetWebACL",
                          + "wafv2:DisassociateWebACL",
                          + "wafv2:AssociateWebACL",
                          + "waf-regional:GetWebACLForResource",
                          + "waf-regional:GetWebACL",
                          + "waf-regional:DisassociateWebACL",
                          + "waf-regional:AssociateWebACL",
                          + "shield:GetSubscriptionState",
                          + "shield:DescribeProtection",
                          + "shield:DeleteProtection",
                          + "shield:CreateProtection",
                          + "iam:ListServerCertificates",
                          + "iam:GetServerCertificate",
                          + "cognito-idp:DescribeUserPoolClient",
                          + "acm:ListCertificates",
                          + "acm:DescribeCertificate",
                        ]
                      + Effect   = "Allow"
                      + Resource = "*"
                    },
                  + {
                      + Action   = [
                          + "ec2:RevokeSecurityGroupIngress",
                          + "ec2:CreateSecurityGroup",
                          + "ec2:AuthorizeSecurityGroupIngress",
                        ]
                      + Effect   = "Allow"
                      + Resource = "*"
                    },
                  + {
                      + Action    = "ec2:CreateTags"
                      + Condition = {
                          + Null         = {
                              + "aws:RequestTag/elbv2.k8s.aws/cluster" = "false"
                            }
                          + StringEquals = {
                              + "ec2:CreateAction" = "CreateSecurityGroup"
                            }
                        }
                      + Effect    = "Allow"
                      + Resource  = "arn:aws:ec2:*:*:security-group/*"
                    },
                  + {
                      + Action    = [
                          + "ec2:DeleteTags",
                          + "ec2:CreateTags",
                        ]
                      + Condition = {
                          + Null = {
                              + "aws:RequestTag/elbv2.k8s.aws/cluster"  = "true"
                              + "aws:ResourceTag/elbv2.k8s.aws/cluster" = "false"
                            }
                        }
                      + Effect    = "Allow"
                      + Resource  = "arn:aws:ec2:*:*:security-group/*"
                    },
                  + {
                      + Action    = [
                          + "ec2:RevokeSecurityGroupIngress",
                          + "ec2:DeleteSecurityGroup",
                          + "ec2:AuthorizeSecurityGroupIngress",
                        ]
                      + Condition = {
                          + Null = {
                              + "aws:ResourceTag/elbv2.k8s.aws/cluster" = "false"
                            }
                        }
                      + Effect    = "Allow"
                      + Resource  = "*"
                    },
                  + {
                      + Action    = [
                          + "elasticloadbalancing:CreateTargetGroup",
                          + "elasticloadbalancing:CreateLoadBalancer",
                          + "elasticloadbalancing:AddTags",
                        ]
                      + Condition = {
                          + Null = {
                              + "aws:RequestTag/elbv2.k8s.aws/cluster" = "false"
                            }
                        }
                      + Effect    = "Allow"
                      + Resource  = "*"
                    },
                  + {
                      + Action   = [
                          + "elasticloadbalancing:DeleteRule",
                          + "elasticloadbalancing:DeleteListener",
                          + "elasticloadbalancing:CreateRule",
                          + "elasticloadbalancing:CreateListener",
                          + "elasticloadbalancing:AddTags",
                        ]
                      + Effect   = "Allow"
                      + Resource = "*"
                    },
                  + {
                      + Action    = [
                          + "elasticloadbalancing:RemoveTags",
                          + "elasticloadbalancing:AddTags",
                        ]
                      + Condition = {
                          + Null = {
                              + "aws:RequestTag/elbv2.k8s.aws/cluster"  = "true"
                              + "aws:ResourceTag/elbv2.k8s.aws/cluster" = "false"
                            }
                        }
                      + Effect    = "Allow"
                      + Resource  = [
                          + "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*",
                          + "arn:aws:elasticloadbalancing:*:*:loadbalancer/net/*/*",
                          + "arn:aws:elasticloadbalancing:*:*:loadbalancer/app/*/*",
                        ]
                    },
                  + {
                      + Action   = [
                          + "elasticloadbalancing:RemoveTags",
                          + "elasticloadbalancing:AddTags",
                        ]
                      + Effect   = "Allow"
                      + Resource = [
                          + "arn:aws:elasticloadbalancing:*:*:listener/net/*/*/*",
                          + "arn:aws:elasticloadbalancing:*:*:listener/app/*/*/*",
                          + "arn:aws:elasticloadbalancing:*:*:listener-rule/net/*/*/*",
                          + "arn:aws:elasticloadbalancing:*:*:listener-rule/app/*/*/*",
                        ]
                    },
                  + {
                      + Action    = [
                          + "elasticloadbalancing:SetSubnets",
                          + "elasticloadbalancing:SetSecurityGroups",
                          + "elasticloadbalancing:SetIpAddressType",
                          + "elasticloadbalancing:ModifyTargetGroupAttributes",
                          + "elasticloadbalancing:ModifyTargetGroup",
                          + "elasticloadbalancing:ModifyLoadBalancerAttributes",
                          + "elasticloadbalancing:DeleteTargetGroup",
                          + "elasticloadbalancing:DeleteLoadBalancer",
                        ]
                      + Condition = {
                          + Null = {
                              + "aws:ResourceTag/elbv2.k8s.aws/cluster" = "false"
                            }
                        }
                      + Effect    = "Allow"
                      + Resource  = "*"
                    },
                  + {
                      + Action    = "elasticloadbalancing:AddTags"
                      + Condition = {
                          + Null         = {
                              + "aws:RequestTag/elbv2.k8s.aws/cluster" = "false"
                            }
                          + StringEquals = {
                              + "elasticloadbalancing:CreateAction" = [
                                  + "CreateTargetGroup",
                                  + "CreateLoadBalancer",
                                ]
                            }
                        }
                      + Effect    = "Allow"
                      + Resource  = [
                          + "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*",
                          + "arn:aws:elasticloadbalancing:*:*:loadbalancer/net/*/*",
                          + "arn:aws:elasticloadbalancing:*:*:loadbalancer/app/*/*",
                        ]
                    },
                  + {
                      + Action   = [
                          + "elasticloadbalancing:RegisterTargets",
                          + "elasticloadbalancing:DeregisterTargets",
                        ]
                      + Effect   = "Allow"
                      + Resource = "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*"
                    },
                  + {
                      + Action   = [
                          + "elasticloadbalancing:SetWebAcl",
                          + "elasticloadbalancing:RemoveListenerCertificates",
                          + "elasticloadbalancing:ModifyRule",
                          + "elasticloadbalancing:ModifyListener",
                          + "elasticloadbalancing:AddListenerCertificates",
                        ]
                      + Effect   = "Allow"
                      + Resource = "*"
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + policy_id   = (known after apply)
      + tags_all    = (known after apply)
    }

  # module.lb_role.aws_iam_role.this[0] will be created
  + resource "aws_iam_role" "this" {
      + arn                   = (known after apply)
      + assume_role_policy    = (known after apply)
      + create_date           = (known after apply)
      + force_detach_policies = true
      + id                    = (known after apply)
      + managed_policy_arns   = (known after apply)
      + max_session_duration  = 3600
      + name                  = "k8s-devsu-demo_eks_lb"
      + name_prefix           = (known after apply)
      + path                  = "/"
      + tags_all              = (known after apply)
      + unique_id             = (known after apply)
    }

  # module.lb_role.aws_iam_role_policy_attachment.load_balancer_controller[0] will be created
  + resource "aws_iam_role_policy_attachment" "load_balancer_controller" {
      + id         = (known after apply)
      + policy_arn = (known after apply)
      + role       = "k8s-devsu-demo_eks_lb"
    }

  # module.vpc.aws_default_network_acl.this[0] will be created
  + resource "aws_default_network_acl" "this" {
      + arn                    = (known after apply)
      + default_network_acl_id = (known after apply)
      + id                     = (known after apply)
      + owner_id               = (known after apply)
      + tags                   = {
          + "Name" = "vpc-devsu-demo-default"
        }
      + tags_all               = {
          + "Name" = "vpc-devsu-demo-default"
        }
      + vpc_id                 = (known after apply)

      + egress {
          + action          = "allow"
          + from_port       = 0
          + ipv6_cidr_block = "::/0"
          + protocol        = "-1"
          + rule_no         = 101
          + to_port         = 0
        }
      + egress {
          + action     = "allow"
          + cidr_block = "0.0.0.0/0"
          + from_port  = 0
          + protocol   = "-1"
          + rule_no    = 100
          + to_port    = 0
        }

      + ingress {
          + action          = "allow"
          + from_port       = 0
          + ipv6_cidr_block = "::/0"
          + protocol        = "-1"
          + rule_no         = 101
          + to_port         = 0
        }
      + ingress {
          + action     = "allow"
          + cidr_block = "0.0.0.0/0"
          + from_port  = 0
          + protocol   = "-1"
          + rule_no    = 100
          + to_port    = 0
        }
    }

  # module.vpc.aws_default_route_table.default[0] will be created
  + resource "aws_default_route_table" "default" {
      + arn                    = (known after apply)
      + default_route_table_id = (known after apply)
      + id                     = (known after apply)
      + owner_id               = (known after apply)
      + route                  = (known after apply)
      + tags                   = {
          + "Name" = "vpc-devsu-demo-default"
        }
      + tags_all               = {
          + "Name" = "vpc-devsu-demo-default"
        }
      + vpc_id                 = (known after apply)

      + timeouts {
          + create = "5m"
          + update = "5m"
        }
    }

  # module.vpc.aws_default_security_group.this[0] will be created
  + resource "aws_default_security_group" "this" {
      + arn                    = (known after apply)
      + description            = (known after apply)
      + egress                 = (known after apply)
      + id                     = (known after apply)
      + ingress                = (known after apply)
      + name                   = (known after apply)
      + name_prefix            = (known after apply)
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = {
          + "Name" = "vpc-devsu-demo-default"
        }
      + tags_all               = {
          + "Name" = "vpc-devsu-demo-default"
        }
      + vpc_id                 = (known after apply)
    }

  # module.vpc.aws_eip.nat[0] will be created
  + resource "aws_eip" "nat" {
      + allocation_id        = (known after apply)
      + association_id       = (known after apply)
      + carrier_ip           = (known after apply)
      + customer_owned_ip    = (known after apply)
      + domain               = "vpc"
      + id                   = (known after apply)
      + instance             = (known after apply)
      + network_border_group = (known after apply)
      + network_interface    = (known after apply)
      + private_dns          = (known after apply)
      + private_ip           = (known after apply)
      + public_dns           = (known after apply)
      + public_ip            = (known after apply)
      + public_ipv4_pool     = (known after apply)
      + tags                 = {
          + "Name" = "vpc-devsu-demo-us-east-1a"
        }
      + tags_all             = {
          + "Name" = "vpc-devsu-demo-us-east-1a"
        }
      + vpc                  = (known after apply)
    }

  # module.vpc.aws_internet_gateway.this[0] will be created
  + resource "aws_internet_gateway" "this" {
      + arn      = (known after apply)
      + id       = (known after apply)
      + owner_id = (known after apply)
      + tags     = {
          + "Name" = "vpc-devsu-demo"
        }
      + tags_all = {
          + "Name" = "vpc-devsu-demo"
        }
      + vpc_id   = (known after apply)
    }

  # module.vpc.aws_nat_gateway.this[0] will be created
  + resource "aws_nat_gateway" "this" {
      + allocation_id        = (known after apply)
      + association_id       = (known after apply)
      + connectivity_type    = "public"
      + id                   = (known after apply)
      + network_interface_id = (known after apply)
      + private_ip           = (known after apply)
      + public_ip            = (known after apply)
      + subnet_id            = (known after apply)
      + tags                 = {
          + "Name" = "vpc-devsu-demo-us-east-1a"
        }
      + tags_all             = {
          + "Name" = "vpc-devsu-demo-us-east-1a"
        }
    }

  # module.vpc.aws_route.private_nat_gateway[0] will be created
  + resource "aws_route" "private_nat_gateway" {
      + destination_cidr_block = "0.0.0.0/0"
      + id                     = (known after apply)
      + instance_id            = (known after apply)
      + instance_owner_id      = (known after apply)
      + nat_gateway_id         = (known after apply)
      + network_interface_id   = (known after apply)
      + origin                 = (known after apply)
      + route_table_id         = (known after apply)
      + state                  = (known after apply)

      + timeouts {
          + create = "5m"
        }
    }

  # module.vpc.aws_route.public_internet_gateway[0] will be created
  + resource "aws_route" "public_internet_gateway" {
      + destination_cidr_block = "0.0.0.0/0"
      + gateway_id             = (known after apply)
      + id                     = (known after apply)
      + instance_id            = (known after apply)
      + instance_owner_id      = (known after apply)
      + network_interface_id   = (known after apply)
      + origin                 = (known after apply)
      + route_table_id         = (known after apply)
      + state                  = (known after apply)

      + timeouts {
          + create = "5m"
        }
    }

  # module.vpc.aws_route_table.private[0] will be created
  + resource "aws_route_table" "private" {
      + arn              = (known after apply)
      + id               = (known after apply)
      + owner_id         = (known after apply)
      + propagating_vgws = (known after apply)
      + route            = (known after apply)
      + tags             = {
          + "Name" = "vpc-devsu-demo-private"
        }
      + tags_all         = {
          + "Name" = "vpc-devsu-demo-private"
        }
      + vpc_id           = (known after apply)
    }

  # module.vpc.aws_route_table.public[0] will be created
  + resource "aws_route_table" "public" {
      + arn              = (known after apply)
      + id               = (known after apply)
      + owner_id         = (known after apply)
      + propagating_vgws = (known after apply)
      + route            = (known after apply)
      + tags             = {
          + "Name" = "vpc-devsu-demo-public"
        }
      + tags_all         = {
          + "Name" = "vpc-devsu-demo-public"
        }
      + vpc_id           = (known after apply)
    }

  # module.vpc.aws_route_table_association.private[0] will be created
  + resource "aws_route_table_association" "private" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # module.vpc.aws_route_table_association.private[1] will be created
  + resource "aws_route_table_association" "private" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # module.vpc.aws_route_table_association.private[2] will be created
  + resource "aws_route_table_association" "private" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # module.vpc.aws_route_table_association.public[0] will be created
  + resource "aws_route_table_association" "public" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # module.vpc.aws_route_table_association.public[1] will be created
  + resource "aws_route_table_association" "public" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # module.vpc.aws_route_table_association.public[2] will be created
  + resource "aws_route_table_association" "public" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # module.vpc.aws_subnet.private[0] will be created
  + resource "aws_subnet" "private" {
      + arn                                            = (known after apply)
      + assign_ipv6_address_on_creation                = false
      + availability_zone                              = "us-east-1a"
      + availability_zone_id                           = (known after apply)
      + cidr_block                                     = "10.0.1.0/24"
      + enable_dns64                                   = false
      + enable_resource_name_dns_a_record_on_launch    = false
      + enable_resource_name_dns_aaaa_record_on_launch = false
      + id                                             = (known after apply)
      + ipv6_cidr_block_association_id                 = (known after apply)
      + ipv6_native                                    = false
      + map_public_ip_on_launch                        = false
      + owner_id                                       = (known after apply)
      + private_dns_hostname_type_on_launch            = (known after apply)
      + tags                                           = {
          + "Name"                                 = "vpc-devsu-demo-private-us-east-1a"
          + "kubernetes.io/cluster/k8s-devsu-demo" = "shared"
          + "kubernetes.io/role/internal-elb"      = "1"
        }
      + tags_all                                       = {
          + "Name"                                 = "vpc-devsu-demo-private-us-east-1a"
          + "kubernetes.io/cluster/k8s-devsu-demo" = "shared"
          + "kubernetes.io/role/internal-elb"      = "1"
        }
      + vpc_id                                         = (known after apply)
    }

  # module.vpc.aws_subnet.private[1] will be created
  + resource "aws_subnet" "private" {
      + arn                                            = (known after apply)
      + assign_ipv6_address_on_creation                = false
      + availability_zone                              = "us-east-1b"
      + availability_zone_id                           = (known after apply)
      + cidr_block                                     = "10.0.2.0/24"
      + enable_dns64                                   = false
      + enable_resource_name_dns_a_record_on_launch    = false
      + enable_resource_name_dns_aaaa_record_on_launch = false
      + id                                             = (known after apply)
      + ipv6_cidr_block_association_id                 = (known after apply)
      + ipv6_native                                    = false
      + map_public_ip_on_launch                        = false
      + owner_id                                       = (known after apply)
      + private_dns_hostname_type_on_launch            = (known after apply)
      + tags                                           = {
          + "Name"                                 = "vpc-devsu-demo-private-us-east-1b"
          + "kubernetes.io/cluster/k8s-devsu-demo" = "shared"
          + "kubernetes.io/role/internal-elb"      = "1"
        }
      + tags_all                                       = {
          + "Name"                                 = "vpc-devsu-demo-private-us-east-1b"
          + "kubernetes.io/cluster/k8s-devsu-demo" = "shared"
          + "kubernetes.io/role/internal-elb"      = "1"
        }
      + vpc_id                                         = (known after apply)
    }

  # module.vpc.aws_subnet.private[2] will be created
  + resource "aws_subnet" "private" {
      + arn                                            = (known after apply)
      + assign_ipv6_address_on_creation                = false
      + availability_zone                              = "us-east-1c"
      + availability_zone_id                           = (known after apply)
      + cidr_block                                     = "10.0.3.0/24"
      + enable_dns64                                   = false
      + enable_resource_name_dns_a_record_on_launch    = false
      + enable_resource_name_dns_aaaa_record_on_launch = false
      + id                                             = (known after apply)
      + ipv6_cidr_block_association_id                 = (known after apply)
      + ipv6_native                                    = false
      + map_public_ip_on_launch                        = false
      + owner_id                                       = (known after apply)
      + private_dns_hostname_type_on_launch            = (known after apply)
      + tags                                           = {
          + "Name"                                 = "vpc-devsu-demo-private-us-east-1c"
          + "kubernetes.io/cluster/k8s-devsu-demo" = "shared"
          + "kubernetes.io/role/internal-elb"      = "1"
        }
      + tags_all                                       = {
          + "Name"                                 = "vpc-devsu-demo-private-us-east-1c"
          + "kubernetes.io/cluster/k8s-devsu-demo" = "shared"
          + "kubernetes.io/role/internal-elb"      = "1"
        }
      + vpc_id                                         = (known after apply)
    }

  # module.vpc.aws_subnet.public[0] will be created
  + resource "aws_subnet" "public" {
      + arn                                            = (known after apply)
      + assign_ipv6_address_on_creation                = false
      + availability_zone                              = "us-east-1a"
      + availability_zone_id                           = (known after apply)
      + cidr_block                                     = "10.0.4.0/24"
      + enable_dns64                                   = false
      + enable_resource_name_dns_a_record_on_launch    = false
      + enable_resource_name_dns_aaaa_record_on_launch = false
      + id                                             = (known after apply)
      + ipv6_cidr_block_association_id                 = (known after apply)
      + ipv6_native                                    = false
      + map_public_ip_on_launch                        = false
      + owner_id                                       = (known after apply)
      + private_dns_hostname_type_on_launch            = (known after apply)
      + tags                                           = {
          + "Name"                                 = "vpc-devsu-demo-public-us-east-1a"
          + "kubernetes.io/cluster/k8s-devsu-demo" = "shared"
          + "kubernetes.io/role/elb"               = "1"
        }
      + tags_all                                       = {
          + "Name"                                 = "vpc-devsu-demo-public-us-east-1a"
          + "kubernetes.io/cluster/k8s-devsu-demo" = "shared"
          + "kubernetes.io/role/elb"               = "1"
        }
      + vpc_id                                         = (known after apply)
    }

  # module.vpc.aws_subnet.public[1] will be created
  + resource "aws_subnet" "public" {
      + arn                                            = (known after apply)
      + assign_ipv6_address_on_creation                = false
      + availability_zone                              = "us-east-1b"
      + availability_zone_id                           = (known after apply)
      + cidr_block                                     = "10.0.5.0/24"
      + enable_dns64                                   = false
      + enable_resource_name_dns_a_record_on_launch    = false
      + enable_resource_name_dns_aaaa_record_on_launch = false
      + id                                             = (known after apply)
      + ipv6_cidr_block_association_id                 = (known after apply)
      + ipv6_native                                    = false
      + map_public_ip_on_launch                        = false
      + owner_id                                       = (known after apply)
      + private_dns_hostname_type_on_launch            = (known after apply)
      + tags                                           = {
          + "Name"                                 = "vpc-devsu-demo-public-us-east-1b"
          + "kubernetes.io/cluster/k8s-devsu-demo" = "shared"
          + "kubernetes.io/role/elb"               = "1"
        }
      + tags_all                                       = {
          + "Name"                                 = "vpc-devsu-demo-public-us-east-1b"
          + "kubernetes.io/cluster/k8s-devsu-demo" = "shared"
          + "kubernetes.io/role/elb"               = "1"
        }
      + vpc_id                                         = (known after apply)
    }

  # module.vpc.aws_subnet.public[2] will be created
  + resource "aws_subnet" "public" {
      + arn                                            = (known after apply)
      + assign_ipv6_address_on_creation                = false
      + availability_zone                              = "us-east-1c"
      + availability_zone_id                           = (known after apply)
      + cidr_block                                     = "10.0.6.0/24"
      + enable_dns64                                   = false
      + enable_resource_name_dns_a_record_on_launch    = false
      + enable_resource_name_dns_aaaa_record_on_launch = false
      + id                                             = (known after apply)
      + ipv6_cidr_block_association_id                 = (known after apply)
      + ipv6_native                                    = false
      + map_public_ip_on_launch                        = false
      + owner_id                                       = (known after apply)
      + private_dns_hostname_type_on_launch            = (known after apply)
      + tags                                           = {
          + "Name"                                 = "vpc-devsu-demo-public-us-east-1c"
          + "kubernetes.io/cluster/k8s-devsu-demo" = "shared"
          + "kubernetes.io/role/elb"               = "1"
        }
      + tags_all                                       = {
          + "Name"                                 = "vpc-devsu-demo-public-us-east-1c"
          + "kubernetes.io/cluster/k8s-devsu-demo" = "shared"
          + "kubernetes.io/role/elb"               = "1"
        }
      + vpc_id                                         = (known after apply)
    }

  # module.vpc.aws_vpc.this[0] will be created
  + resource "aws_vpc" "this" {
      + arn                                  = (known after apply)
      + cidr_block                           = "10.0.0.0/16"
      + default_network_acl_id               = (known after apply)
      + default_route_table_id               = (known after apply)
      + default_security_group_id            = (known after apply)
      + dhcp_options_id                      = (known after apply)
      + enable_dns_hostnames                 = true
      + enable_dns_support                   = true
      + enable_network_address_usage_metrics = (known after apply)
      + id                                   = (known after apply)
      + instance_tenancy                     = "default"
      + ipv6_association_id                  = (known after apply)
      + ipv6_cidr_block                      = (known after apply)
      + ipv6_cidr_block_network_border_group = (known after apply)
      + main_route_table_id                  = (known after apply)
      + owner_id                             = (known after apply)
      + tags                                 = {
          + "Name" = "vpc-devsu-demo"
        }
      + tags_all                             = {
          + "Name" = "vpc-devsu-demo"
        }
    }

  # module.eks.module.eks_managed_node_group["one"].aws_eks_node_group.this[0] will be created
  + resource "aws_eks_node_group" "this" {
      + ami_type               = "AL2_x86_64"
      + arn                    = (known after apply)
      + capacity_type          = (known after apply)
      + cluster_name           = "k8s-devsu-demo"
      + disk_size              = (known after apply)
      + id                     = (known after apply)
      + instance_types         = [
          + "t3a.medium",
        ]
      + node_group_name        = (known after apply)
      + node_group_name_prefix = "node-group-1-"
      + node_role_arn          = (known after apply)
      + release_version        = (known after apply)
      + resources              = (known after apply)
      + status                 = (known after apply)
      + subnet_ids             = (known after apply)
      + tags                   = {
          + "Name" = "node-group-1"
        }
      + tags_all               = {
          + "Name" = "node-group-1"
        }
      + version                = "1.27"

      + launch_template {
          + id      = (known after apply)
          + name    = (known after apply)
          + version = (known after apply)
        }

      + scaling_config {
          + desired_size = 1
          + max_size     = 2
          + min_size     = 1
        }

      + timeouts {}

      + update_config {
          + max_unavailable_percentage = 33
        }
    }

  # module.eks.module.eks_managed_node_group["one"].aws_iam_role.this[0] will be created
  + resource "aws_iam_role" "this" {
      + arn                   = (known after apply)
      + assume_role_policy    = jsonencode(
            {
              + Statement = [
                  + {
                      + Action    = "sts:AssumeRole"
                      + Effect    = "Allow"
                      + Principal = {
                          + Service = "ec2.amazonaws.com"
                        }
                      + Sid       = "EKSNodeAssumeRole"
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + create_date           = (known after apply)
      + description           = "EKS managed node group IAM role"
      + force_detach_policies = true
      + id                    = (known after apply)
      + managed_policy_arns   = (known after apply)
      + max_session_duration  = 3600
      + name                  = (known after apply)
      + name_prefix           = "node-group-1-eks-node-group-"
      + path                  = "/"
      + tags_all              = (known after apply)
      + unique_id             = (known after apply)
    }

  # module.eks.module.eks_managed_node_group["one"].aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"] will be created
  + resource "aws_iam_role_policy_attachment" "this" {
      + id         = (known after apply)
      + policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
      + role       = (known after apply)
    }

  # module.eks.module.eks_managed_node_group["one"].aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"] will be created
  + resource "aws_iam_role_policy_attachment" "this" {
      + id         = (known after apply)
      + policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
      + role       = (known after apply)
    }

  # module.eks.module.eks_managed_node_group["one"].aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"] will be created
  + resource "aws_iam_role_policy_attachment" "this" {
      + id         = (known after apply)
      + policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
      + role       = (known after apply)
    }

  # module.eks.module.eks_managed_node_group["one"].aws_launch_template.this[0] will be created
  + resource "aws_launch_template" "this" {
      + arn                    = (known after apply)
      + default_version        = (known after apply)
      + description            = "Custom launch template for node-group-1 EKS managed node group"
      + id                     = (known after apply)
      + latest_version         = (known after apply)
      + name                   = (known after apply)
      + name_prefix            = "one-"
      + tags_all               = (known after apply)
      + update_default_version = true
      + vpc_security_group_ids = (known after apply)

      + metadata_options {
          + http_endpoint               = "enabled"
          + http_protocol_ipv6          = (known after apply)
          + http_put_response_hop_limit = 2
          + http_tokens                 = "required"
          + instance_metadata_tags      = (known after apply)
        }

      + monitoring {
          + enabled = true
        }

      + tag_specifications {
          + resource_type = "instance"
          + tags          = {
              + "Name" = "node-group-1"
            }
        }
      + tag_specifications {
          + resource_type = "network-interface"
          + tags          = {
              + "Name" = "node-group-1"
            }
        }
      + tag_specifications {
          + resource_type = "volume"
          + tags          = {
              + "Name" = "node-group-1"
            }
        }
    }

  # module.eks.module.kms.data.aws_iam_policy_document.this[0] will be read during apply
  # (config refers to values not yet known)
 <= data "aws_iam_policy_document" "this" {
      + id                        = (known after apply)
      + json                      = (known after apply)
      + override_policy_documents = []
      + source_policy_documents   = []

      + statement {
          + actions   = [
              + "kms:CancelKeyDeletion",
              + "kms:Create*",
              + "kms:Delete*",
              + "kms:Describe*",
              + "kms:Disable*",
              + "kms:Enable*",
              + "kms:Get*",
              + "kms:List*",
              + "kms:Put*",
              + "kms:Revoke*",
              + "kms:ScheduleKeyDeletion",
              + "kms:TagResource",
              + "kms:UntagResource",
              + "kms:Update*",
            ]
          + resources = [
              + "*",
            ]
          + sid       = "KeyAdministration"

          + principals {
              + identifiers = [
                  + "arn:aws:iam::951903200613:user/Admin",
                ]
              + type        = "AWS"
            }
        }
      + statement {
          + actions   = [
              + "kms:Decrypt",
              + "kms:DescribeKey",
              + "kms:Encrypt",
              + "kms:GenerateDataKey*",
              + "kms:ReEncrypt*",
            ]
          + resources = [
              + "*",
            ]
          + sid       = "KeyUsage"

          + principals {
              + identifiers = [
                  + (known after apply),
                ]
              + type        = "AWS"
            }
        }
    }

  # module.eks.module.kms.aws_kms_alias.this["cluster"] will be created
  + resource "aws_kms_alias" "this" {
      + arn            = (known after apply)
      + id             = (known after apply)
      + name           = "alias/eks/k8s-devsu-demo"
      + name_prefix    = (known after apply)
      + target_key_arn = (known after apply)
      + target_key_id  = (known after apply)
    }

  # module.eks.module.kms.aws_kms_key.this[0] will be created
  + resource "aws_kms_key" "this" {
      + arn                                = (known after apply)
      + bypass_policy_lockout_safety_check = false
      + customer_master_key_spec           = "SYMMETRIC_DEFAULT"
      + description                        = "k8s-devsu-demo cluster encryption key"
      + enable_key_rotation                = true
      + id                                 = (known after apply)
      + is_enabled                         = true
      + key_id                             = (known after apply)
      + key_usage                          = "ENCRYPT_DECRYPT"
      + multi_region                       = false
      + policy                             = (known after apply)
      + tags_all                           = (known after apply)
    }

Plan: 69 to add, 0 to change, 0 to destroy.

Changes to Outputs:
  + access_id        = (known after apply)
  + access_secret    = (known after apply)
  + cluster_endpoint = (known after apply)
  + cluster_name     = "k8s-devsu-demo"

Do you want to perform these actions?
  Terraform will perform the actions described above.
  Only 'yes' will be accepted to approve.

  Enter a value: yes

module.vpc.aws_vpc.this[0]: Creating...
aws_iam_group.iam_group: Creating...
module.eks.aws_cloudwatch_log_group.this[0]: Creating...
module.eks.module.eks_managed_node_group["one"].aws_iam_role.this[0]: Creating...
module.eks.aws_iam_role.this[0]: Creating...
aws_iam_policy.iam_ecr_policy: Creating...
aws_iam_user.iam_user: Creating...
module.lb_role.aws_iam_policy.load_balancer_controller[0]: Creating...
aws_iam_user.iam_user: Creation complete after 1s [id=gh_action]
aws_iam_access_key.access_ecr: Creating...
aws_iam_group.iam_group: Creation complete after 1s [id=gh_action]
aws_iam_policy.iam_ecr_policy: Creation complete after 1s [id=arn:aws:iam::951903200613:policy/gh_action-ecr-push-policy]
module.lb_role.aws_iam_policy.load_balancer_controller[0]: Creation complete after 2s [id=arn:aws:iam::951903200613:policy/AmazonEKS_AWS_Load_Balancer_Controller-20230801155301360700000003]
aws_iam_access_key.access_ecr: Creation complete after 1s [id=AKIA53IO2EVSZFENACQA]
aws_iam_group_membership.main: Creating...
module.eks.module.eks_managed_node_group["one"].aws_iam_role.this[0]: Creation complete after 2s [id=node-group-1-eks-node-group-20230801155301357400000001]
aws_iam_group_policy_attachment.grant_access: Creating...
module.eks.aws_cloudwatch_log_group.this[0]: Creation complete after 2s [id=/aws/eks/k8s-devsu-demo/cluster]
module.eks.module.eks_managed_node_group["one"].aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"]: Creating...
module.eks.module.eks_managed_node_group["one"].aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"]: Creating...
module.eks.module.eks_managed_node_group["one"].aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"]: Creating...
aws_iam_group_membership.main: Creation complete after 0s [id=gh_action-ecr-access]
module.eks.aws_iam_role.this[0]: Creation complete after 2s [id=k8s-devsu-demo-cluster-20230801155301358800000002]
aws_iam_group_policy_attachment.grant_access: Creation complete after 0s [id=gh_action-20230801155302964500000004]
module.eks.aws_iam_role_policy_attachment.this["AmazonEKSVPCResourceController"]: Creating...
module.eks.aws_iam_role_policy_attachment.this["AmazonEKSClusterPolicy"]: Creating...
module.eks.module.kms.data.aws_iam_policy_document.this[0]: Reading...
module.eks.module.kms.data.aws_iam_policy_document.this[0]: Read complete after 0s [id=3915584489]
module.eks.module.eks_managed_node_group["one"].aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"]: Creation complete after 0s [id=node-group-1-eks-node-group-20230801155301357400000001-20230801155303071700000005]
module.eks.module.eks_managed_node_group["one"].aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"]: Creation complete after 0s [id=node-group-1-eks-node-group-20230801155301357400000001-20230801155303089700000006]
module.eks.module.eks_managed_node_group["one"].aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"]: Creation complete after 0s [id=node-group-1-eks-node-group-20230801155301357400000001-20230801155303122400000007]
module.eks.module.kms.aws_kms_key.this[0]: Creating...
module.eks.aws_iam_role_policy_attachment.this["AmazonEKSClusterPolicy"]: Creation complete after 1s [id=k8s-devsu-demo-cluster-20230801155301358800000002-20230801155303431700000008]
module.eks.aws_iam_role_policy_attachment.this["AmazonEKSVPCResourceController"]: Creation complete after 1s [id=k8s-devsu-demo-cluster-20230801155301358800000002-20230801155303443100000009]
module.vpc.aws_vpc.this[0]: Still creating... [10s elapsed]
module.eks.module.kms.aws_kms_key.this[0]: Still creating... [10s elapsed]
module.vpc.aws_vpc.this[0]: Creation complete after 14s [id=vpc-07913f1ad48c3dbf8]
module.vpc.aws_default_route_table.default[0]: Creating...
module.vpc.aws_default_security_group.this[0]: Creating...
module.eks.aws_security_group.node[0]: Creating...
module.vpc.aws_internet_gateway.this[0]: Creating...
module.vpc.aws_subnet.private[1]: Creating...
module.eks.aws_security_group.cluster[0]: Creating...
module.vpc.aws_subnet.private[0]: Creating...
module.vpc.aws_default_network_acl.this[0]: Creating...
module.vpc.aws_subnet.private[2]: Creating...
module.vpc.aws_default_route_table.default[0]: Creation complete after 1s [id=rtb-03814634aa2a0bb70]
module.vpc.aws_route_table.public[0]: Creating...
module.vpc.aws_internet_gateway.this[0]: Creation complete after 1s [id=igw-0ed3d34eac31dfb6b]
module.vpc.aws_subnet.private[0]: Creation complete after 1s [id=subnet-02db1b6442f8175e4]
module.vpc.aws_subnet.private[2]: Creation complete after 1s [id=subnet-072c5f6b87c27084a]
module.vpc.aws_route_table.private[0]: Creating...
module.vpc.aws_subnet.private[1]: Creation complete after 2s [id=subnet-090035cbc1ac3a3eb]
module.vpc.aws_subnet.public[2]: Creating...
module.vpc.aws_subnet.public[0]: Creating...
module.vpc.aws_subnet.public[1]: Creating...
module.vpc.aws_route_table.public[0]: Creation complete after 1s [id=rtb-0133586090119e728]
module.vpc.aws_eip.nat[0]: Creating...
module.vpc.aws_default_security_group.this[0]: Creation complete after 3s [id=sg-08ad1b6c67d8ebc91]
module.vpc.aws_route.public_internet_gateway[0]: Creating...
module.vpc.aws_route_table.private[0]: Creation complete after 1s [id=rtb-0d7d2ff3c2491baaf]
module.vpc.aws_subnet.public[2]: Creation complete after 1s [id=subnet-0932a3891c9e9d529]
module.vpc.aws_default_network_acl.this[0]: Creation complete after 3s [id=acl-0dffda8121fa750e0]
module.vpc.aws_subnet.public[0]: Creation complete after 1s [id=subnet-00826485af14235be]
module.vpc.aws_route_table_association.private[0]: Creating...
module.vpc.aws_subnet.public[1]: Creation complete after 1s [id=subnet-0c1185ea17af0ef92]
module.vpc.aws_route_table_association.private[2]: Creating...
module.vpc.aws_route_table_association.private[1]: Creating...
module.eks.aws_security_group.node[0]: Creation complete after 3s [id=sg-042db80d7b233408f]
module.vpc.aws_route_table_association.public[2]: Creating...
module.vpc.aws_route_table_association.public[1]: Creating...
module.vpc.aws_route_table_association.public[0]: Creating...
module.eks.aws_security_group.cluster[0]: Creation complete after 3s [id=sg-05f0c9940fe359fd7]
module.vpc.aws_eip.nat[0]: Creation complete after 1s [id=eipalloc-0caeb1497b6cd0b2b]
module.eks.aws_security_group_rule.cluster["ingress_nodes_443"]: Creating...
module.eks.aws_security_group_rule.node["ingress_cluster_8443_webhook"]: Creating...
module.vpc.aws_route_table_association.private[1]: Creation complete after 1s [id=rtbassoc-06eca592eb82393c1]
module.vpc.aws_route_table_association.private[0]: Creation complete after 1s [id=rtbassoc-08d2244b83d15121f]
module.vpc.aws_route_table_association.private[2]: Creation complete after 1s [id=rtbassoc-0bff60e2105929f10]
module.vpc.aws_route_table_association.public[2]: Creation complete after 1s [id=rtbassoc-0e29315fcb59db30e]
module.eks.aws_security_group_rule.node["ingress_cluster_4443_webhook"]: Creating...
module.eks.aws_security_group_rule.node["ingress_cluster_9443_webhook"]: Creating...
module.vpc.aws_route_table_association.public[0]: Creation complete after 1s [id=rtbassoc-04938939dd705ed9e]
module.eks.aws_security_group_rule.node["ingress_cluster_6443_webhook"]: Creating...
module.vpc.aws_route.public_internet_gateway[0]: Creation complete after 1s [id=r-rtb-0133586090119e7281080289494]
module.eks.aws_security_group_rule.node["ingress_nodes_ephemeral"]: Creating...
module.eks.aws_security_group_rule.node["ingress_cluster_443"]: Creating...
module.eks.aws_security_group_rule.node["ingress_self_coredns_tcp"]: Creating...
module.eks.aws_security_group_rule.cluster["ingress_nodes_443"]: Creation complete after 1s [id=sgrule-3569322878]
module.vpc.aws_route_table_association.public[1]: Creation complete after 1s [id=rtbassoc-0469503dfea7c40f9]
module.eks.aws_security_group_rule.node["ingress_cluster_8443_webhook"]: Creation complete after 1s [id=sgrule-1264178694]
module.eks.aws_security_group_rule.node["ingress_self_coredns_udp"]: Creating...
module.eks.aws_security_group_rule.node["ingress_cluster_kubelet"]: Creating...
module.eks.aws_security_group_rule.node["egress_all"]: Creating...
module.eks.aws_security_group_rule.node["ingress_cluster_4443_webhook"]: Creation complete after 1s [id=sgrule-2437385649]
module.vpc.aws_nat_gateway.this[0]: Creating...
module.eks.aws_security_group_rule.node["ingress_cluster_9443_webhook"]: Creation complete after 2s [id=sgrule-804840909]
module.eks.aws_security_group_rule.node["ingress_cluster_6443_webhook"]: Creation complete after 3s [id=sgrule-1476782631]
module.eks.aws_security_group_rule.node["ingress_cluster_443"]: Creation complete after 4s [id=sgrule-79620598]
module.eks.module.kms.aws_kms_key.this[0]: Creation complete after 20s [id=527aae0a-bdeb-488f-8f26-a25d5f36f46f]
module.eks.module.kms.aws_kms_alias.this["cluster"]: Creating...
module.eks.aws_iam_policy.cluster_encryption[0]: Creating...
module.eks.module.kms.aws_kms_alias.this["cluster"]: Creation complete after 0s [id=alias/eks/k8s-devsu-demo]
module.eks.aws_security_group_rule.node["ingress_nodes_ephemeral"]: Creation complete after 5s [id=sgrule-4015208754]
module.eks.aws_iam_policy.cluster_encryption[0]: Creation complete after 1s [id=arn:aws:iam::951903200613:policy/k8s-devsu-demo-cluster-ClusterEncryption2023080115532302870000000d]
module.eks.aws_iam_role_policy_attachment.cluster_encryption[0]: Creating...
module.eks.aws_iam_role_policy_attachment.cluster_encryption[0]: Creation complete after 0s [id=k8s-devsu-demo-cluster-20230801155301358800000002-2023080115532389020000000e]
module.eks.aws_security_group_rule.node["ingress_self_coredns_tcp"]: Creation complete after 5s [id=sgrule-1040069880]
module.eks.aws_security_group_rule.node["ingress_self_coredns_udp"]: Creation complete after 6s [id=sgrule-2577504023]
module.eks.aws_security_group_rule.node["ingress_cluster_kubelet"]: Creation complete after 7s [id=sgrule-3754341189]
module.eks.aws_security_group_rule.node["egress_all"]: Creation complete after 8s [id=sgrule-3075116834]
module.eks.aws_eks_cluster.this[0]: Creating...
module.vpc.aws_nat_gateway.this[0]: Still creating... [10s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [10s elapsed]
module.vpc.aws_nat_gateway.this[0]: Still creating... [20s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [20s elapsed]
module.vpc.aws_nat_gateway.this[0]: Still creating... [30s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [30s elapsed]
module.vpc.aws_nat_gateway.this[0]: Still creating... [40s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [40s elapsed]
module.vpc.aws_nat_gateway.this[0]: Still creating... [50s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [50s elapsed]
module.vpc.aws_nat_gateway.this[0]: Still creating... [1m0s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [1m0s elapsed]
module.vpc.aws_nat_gateway.this[0]: Still creating... [1m10s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [1m10s elapsed]
module.vpc.aws_nat_gateway.this[0]: Still creating... [1m20s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [1m20s elapsed]
module.vpc.aws_nat_gateway.this[0]: Still creating... [1m30s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [1m30s elapsed]
module.vpc.aws_nat_gateway.this[0]: Still creating... [1m40s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [1m40s elapsed]
module.vpc.aws_nat_gateway.this[0]: Creation complete after 1m47s [id=nat-01559e31155b57960]
module.vpc.aws_route.private_nat_gateway[0]: Creating...
module.vpc.aws_route.private_nat_gateway[0]: Creation complete after 2s [id=r-rtb-0d7d2ff3c2491baaf1080289494]
module.eks.aws_eks_cluster.this[0]: Still creating... [1m50s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [2m0s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [2m10s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [2m20s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [2m30s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [2m40s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [2m50s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [3m0s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [3m10s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [3m20s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [3m30s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [3m40s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [3m50s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [4m0s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [4m10s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [4m20s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [4m30s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [4m40s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [4m50s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [5m0s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [5m10s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [5m20s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [5m30s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [5m40s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [5m50s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [6m0s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [6m10s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [6m20s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [6m30s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [6m40s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [6m50s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [7m0s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [7m10s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [7m20s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [7m30s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [7m40s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [7m50s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [8m0s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [8m10s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [8m20s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [8m30s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [8m40s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [8m50s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [9m0s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [9m10s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [9m20s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [9m30s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [9m40s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [9m50s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [10m0s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [10m10s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [10m20s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [10m30s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [10m40s elapsed]
module.eks.aws_eks_cluster.this[0]: Creation complete after 10m44s [id=k8s-devsu-demo]
module.eks.data.tls_certificate.this[0]: Reading...
kubernetes_namespace.sealed-secrets-ns: Creating...
module.eks.time_sleep.this[0]: Creating...
kubernetes_namespace.prod-ns: Creating...
module.eks.data.tls_certificate.this[0]: Read complete after 0s [id=5933588ce34e24e9fb40c3565fb0b5993639df67]
module.eks.aws_iam_openid_connect_provider.oidc_provider[0]: Creating...
module.eks.aws_iam_openid_connect_provider.oidc_provider[0]: Creation complete after 1s [id=arn:aws:iam::951903200613:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/214181C46FD96ED4574B349F64E12E40]
module.lb_role.data.aws_iam_policy_document.this[0]: Reading...
module.lb_role.data.aws_iam_policy_document.this[0]: Read complete after 0s [id=1384250218]
module.lb_role.aws_iam_role.this[0]: Creating...
module.lb_role.aws_iam_role.this[0]: Creation complete after 0s [id=k8s-devsu-demo_eks_lb]
module.lb_role.aws_iam_role_policy_attachment.load_balancer_controller[0]: Creating...
kubernetes_service_account.service-account: Creating...
module.lb_role.aws_iam_role_policy_attachment.load_balancer_controller[0]: Creation complete after 1s [id=k8s-devsu-demo_eks_lb-2023080116041472860000000f]
kubernetes_namespace.sealed-secrets-ns: Creation complete after 3s [id=sealed-secrets]
kubernetes_namespace.prod-ns: Creation complete after 3s [id=prod]
kubernetes_secret.sealed-secrets-key: Creating...
kubernetes_service_account.service-account: Creation complete after 1s [id=kube-system/aws-load-balancer-controller]
kubernetes_secret.sealed-secrets-key: Creation complete after 0s [id=sealed-secrets/sealed-secrets-key]
helm_release.sealed-secrets: Creating...
helm_release.lb: Creating...
module.eks.time_sleep.this[0]: Still creating... [10s elapsed]
helm_release.sealed-secrets: Still creating... [10s elapsed]
helm_release.lb: Still creating... [10s elapsed]
module.eks.time_sleep.this[0]: Still creating... [20s elapsed]
helm_release.sealed-secrets: Still creating... [20s elapsed]
helm_release.lb: Still creating... [20s elapsed]
module.eks.time_sleep.this[0]: Still creating... [30s elapsed]
module.eks.time_sleep.this[0]: Creation complete after 30s [id=2023-08-01T16:04:41Z]
module.eks.module.eks_managed_node_group["one"].aws_launch_template.this[0]: Creating...
module.eks.module.eks_managed_node_group["one"].aws_launch_template.this[0]: Creation complete after 2s [id=lt-0e4aa5c28a08ae86a]
module.eks.module.eks_managed_node_group["one"].aws_eks_node_group.this[0]: Creating...
helm_release.sealed-secrets: Still creating... [30s elapsed]
helm_release.lb: Still creating... [30s elapsed]
module.eks.module.eks_managed_node_group["one"].aws_eks_node_group.this[0]: Still creating... [10s elapsed]
helm_release.sealed-secrets: Still creating... [40s elapsed]
helm_release.lb: Still creating... [40s elapsed]
module.eks.module.eks_managed_node_group["one"].aws_eks_node_group.this[0]: Still creating... [20s elapsed]
helm_release.sealed-secrets: Still creating... [50s elapsed]
helm_release.lb: Still creating... [50s elapsed]
module.eks.module.eks_managed_node_group["one"].aws_eks_node_group.this[0]: Still creating... [30s elapsed]
helm_release.sealed-secrets: Still creating... [1m0s elapsed]
helm_release.lb: Still creating... [1m0s elapsed]
module.eks.module.eks_managed_node_group["one"].aws_eks_node_group.this[0]: Still creating... [40s elapsed]
helm_release.sealed-secrets: Still creating... [1m10s elapsed]
helm_release.lb: Still creating... [1m10s elapsed]
module.eks.module.eks_managed_node_group["one"].aws_eks_node_group.this[0]: Still creating... [50s elapsed]
helm_release.sealed-secrets: Still creating... [1m20s elapsed]
helm_release.lb: Still creating... [1m20s elapsed]
module.eks.module.eks_managed_node_group["one"].aws_eks_node_group.this[0]: Still creating... [1m0s elapsed]
helm_release.sealed-secrets: Still creating... [1m30s elapsed]
helm_release.lb: Still creating... [1m30s elapsed]
module.eks.module.eks_managed_node_group["one"].aws_eks_node_group.this[0]: Still creating... [1m10s elapsed]
helm_release.sealed-secrets: Still creating... [1m40s elapsed]
helm_release.lb: Still creating... [1m40s elapsed]
helm_release.lb: Creation complete after 1m42s [id=aws-load-balancer-controller]
helm_release.sealed-secrets: Creation complete after 1m45s [id=sealed-secrets]
module.eks.module.eks_managed_node_group["one"].aws_eks_node_group.this[0]: Creation complete after 1m20s [id=k8s-devsu-demo:node-group-1-20230801160443882900000012]
helm_release.metrics_server: Creating...
helm_release.metrics_server: Still creating... [10s elapsed]
helm_release.metrics_server: Still creating... [20s elapsed]
helm_release.metrics_server: Still creating... [30s elapsed]
helm_release.metrics_server: Still creating... [40s elapsed]
helm_release.metrics_server: Creation complete after 48s [id=metrics-server]

Apply complete! Resources: 69 added, 0 changed, 0 destroyed.

Outputs:

access_id = "AKIA53IO2EVSZFENACQA"
access_secret = "wcDMA5Y84BrQ8LbaAQwAl6t8IbzWPurtaEV/bzmOCtdQm6ZFJxUUn5OZw9dEFdejbPnR7NXD9OsOrx2grJ5RUiUyrVopetPWTP31lASn+9+2weX2LCSttKsg2v+aN8P434dhgHxa5KokD8Von7w1vAPZDr2sfMKOBo9P5c0G1KAnfE47/SD2CvaC9jjd7hSZavGUePF1zwy0Q6RP0hIuVxB596PJkTvON97S92WZkPNP0fq6iS1DhM8WoQ58tA+pufj8AzWQ7ticcoPeR8HuK84beciFmzbBjEKmmZtusJwoe9PQmvn6zKurTFrqevh+vcZIMizG6y8oyML4igcm9I3DZZbwYyYJqLC21qgUnddrltxeIZ6IXJqCLwWADRz/9L+TTQboL5idrb0z8vV26+CLk31QJelpNq+ImTH3yHZK1C3g4E3PydefhL92vRLrOfqYyPMlNcIsLnqjsJn/HIFOf/f8pERlhXHKdHNG/M1X+rGpa9kkEzSP//6RV1orSh6jwOCHBxXXe5oT5N1b0lkB59h9vytXLcp/obGN0WitQFG5vFc+1A1kI1WYtzJHUcomczCO7Ffh41BQB4XvRFgAWx1KPNPwxyFGfXccewBjMxLrwmy/gMlGj7/gfLqIcmqg4z2yw5k6Cg=="
cluster_endpoint = "https://214181C46FD96ED4574B349F64E12E40.gr7.us-east-1.eks.amazonaws.com"
cluster_name = "k8s-devsu-demo"
```
