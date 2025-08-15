module "acm" {
  source  = "terraform-aws-modules/acm/aws"
  version = "5.2.0"

  domain_name = var.platform_domain_name
  zone_id     = data.aws_route53_zone.this.zone_id

  validation_method = "DNS"

  subject_alternative_names = [
    "*.${var.platform_domain_name}",
  ]

  tags = merge(local.tags, tomap({ "Name" = var.platform_name }))
}

module "alb" {
  source  = "terraform-aws-modules/alb/aws"
  version = "9.17.0"

  name = "${var.platform_name}-ingress-alb"

  vpc_id                = var.vpc_id
  subnets               = var.public_subnets_id
  create_security_group = false
  security_groups       = compact(concat(tolist([local.cluster_security_group_id]), var.infra_public_security_group_ids))
  enable_http2          = false

  listeners = {
    http-https-redirect = {
      port        = 80
      protocol    = "HTTP"
      action_type = "redirect"
      redirect = {
        port        = 443
        protocol    = "HTTPS"
        status_code = "HTTP_301"
      }
    }
    https = {
      port            = 443
      protocol        = "HTTPS"
      ssl_policy      = var.ssl_policy
      certificate_arn = module.acm.acm_certificate_arn

      forward = {
        target_group_key = "http-instance"
      }
    }
  }

  target_groups = {
    http-instance = {
      name                 = "${var.platform_name}-infra-alb-http"
      port                 = 32080
      protocol             = "HTTP"
      deregistration_delay = 20
      create_attachment    = false

      health_check = {
        matcher = 404
      }
    }
  }
  idle_timeout = 500
  access_logs = {
    bucket = "prod-s3-elb-logs-eu-central-1"
  }

  tags = local.tags
}

module "records" {
  source  = "terraform-aws-modules/route53/aws//modules/records"
  version = "5.0.0"

  zone_name = var.platform_domain_name
  records = [
    {
      name = "*"
      type = "A"
      alias = {
        name    = module.alb.dns_name
        zone_id = module.alb.zone_id
      }
    }
  ]
}

module "key_pair" {
  source  = "terraform-aws-modules/key-pair/aws"
  version = "2.1.0"

  key_name              = format("%s-%s", local.cluster_name, "key-pair")
  private_key_algorithm = "ED25519"
  create_private_key    = true

  tags = local.tags
}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "21.0.9"

  enable_cluster_creator_admin_permissions = true
  name                                     = local.cluster_name
  kubernetes_version                       = var.cluster_version
  endpoint_public_access                   = true

  create_iam_role               = true
  iam_role_use_name_prefix      = false
  iam_role_permissions_boundary = var.role_permissions_boundary_arn

  vpc_id     = var.vpc_id
  subnet_ids = var.private_subnets_id

  create_cloudwatch_log_group        = false
  enabled_log_types                  = []
  create_node_security_group         = false
  create_primary_security_group_tags = false

  create_security_group = false
  security_group_id     = local.cluster_security_group_id

  encryption_config = {}

  self_managed_node_groups = {
    worker_group_spot = {
      ami_type                   = "AL2023_x86_64_STANDARD"
      instance_type              = "m7i.xlarge"
      name                       = format("%s-%s", local.cluster_name, "spot")
      subnet_ids                 = [var.private_subnets_id[1]]
      target_group_arns          = [module.alb.target_groups["http-instance"].arn]
      key_name                   = module.key_pair.key_pair_name
      enable_monitoring          = false
      use_mixed_instances_policy = true
      block_device_mappings      = {
        xvda = {
          device_name = "/dev/xvda"
          ebs = {
            volume_size           = 30
            volume_type           = "gp3"
            iops                  = 3000
            throughput            = 150
            encrypted             = false
            delete_on_termination = true
          }
        }
      }

      min_size     = var.spot_min_nodes_count
      max_size     = var.spot_max_nodes_count
      desired_size = var.spot_desired_nodes_count

      iam_role_use_name_prefix      = false
      iam_role_permissions_boundary = var.role_permissions_boundary_arn

      cloudinit_pre_nodeadm = [{
        content      = var.add_userdata
        content_type = "text/x-shellscript; charset=\"us-ascii\""
        },
        {
          content      = <<-EOT
          ---
          apiVersion: node.eks.aws/v1alpha1
          kind: NodeConfig
          spec:
            kubelet:
              flags:
                - --node-labels=node.kubernetes.io/lifecycle=spot
        EOT
          content_type = "application/node.eks.aws"
      }]

      create_iam_instance_profile = true

      mixed_instances_policy = {
        instances_distribution = {
          spot_instance_pools = 2
        }
        launch_template = {
          override = var.spot_instance_types
        }
      }

      # Schedulers
      create_schedule = true
      schedules = {
        "Start" = {
          min_size     = var.spot_min_nodes_count
          max_size     = var.spot_max_nodes_count
          desired_size = var.spot_desired_nodes_count
          recurrence   = "00 6 * * MON-FRI"
          time_zone    = "Etc/UTC"
        },
        "Stop" = {
          min_size     = 0
          max_size     = 0
          desired_size = 0
          recurrence   = "00 18 * * MON-FRI"
          time_zone    = "Etc/UTC"
        },
      }
    },
    worker_group_on_demand = {
      ami_type                   = "AL2023_x86_64_STANDARD"
      instance_type              = "m7i.xlarge"
      name                       = format("%s-%s", local.cluster_name, "on-demand")
      subnet_ids                 = var.private_subnets_id
      target_group_arns          = [module.alb.target_groups["http-instance"].arn]
      key_name                   = module.key_pair.key_pair_name
      enable_monitoring          = false
      use_mixed_instances_policy = true
      block_device_mappings      = {
        xvda = {
          device_name = "/dev/xvda"
          ebs = {
            volume_size           = 30
            volume_type           = "gp3"
            iops                  = 3000
            throughput            = 150
            encrypted             = false
            delete_on_termination = true
          }
        }
      }

      min_size     = var.demand_min_nodes_count
      max_size     = var.demand_max_nodes_count
      desired_size = var.demand_desired_nodes_count

      iam_role_use_name_prefix      = false
      iam_role_permissions_boundary = var.role_permissions_boundary_arn

      cloudinit_pre_nodeadm = [{
        content      = var.add_userdata
        content_type = "text/x-shellscript; charset=\"us-ascii\""
        },
        {
          content      = <<-EOT
          ---
          apiVersion: node.eks.aws/v1alpha1
          kind: NodeConfig
          spec:
            kubelet:
              flags:
                - --node-labels=node.kubernetes.io/lifecycle=normal
        EOT
          content_type = "application/node.eks.aws"
      }]

      create_iam_instance_profile = true

      mixed_instances_policy = {
        launch_template = {
          override = var.spot_instance_types
        }
      }

      # Schedulers
      create_schedule = true
      schedules = {
        "Start" = {
          min_size     = var.demand_min_nodes_count
          max_size     = var.demand_max_nodes_count
          desired_size = var.demand_desired_nodes_count
          recurrence   = "00 6 * * MON-FRI"
          time_zone    = "Etc/UTC"
        },
        "Stop" = {
          min_size     = 0
          max_size     = 0
          desired_size = 0
          recurrence   = "00 18 * * MON-FRI"
          time_zone    = "Etc/UTC"
        },
      }
    },
  }

  # OIDC Identity provider
  identity_providers = var.cluster_identity_providers

  # Addons
  # Verify the addon versions with: aws eks describe-addon-versions --addon-name addon-name --kubernetes-version 1.32
  addons = {
    aws-ebs-csi-driver = {
      addon_version            = "v1.47.0-eksbuild.1"
      resolve_conflicts        = "OVERWRITE"
      service_account_role_arn = module.aws_ebs_csi_driver_irsa.iam_role_arn
    }
    snapshot-controller = {
      addon_version            = "v8.3.0-eksbuild.1"
      resolve_conflicts        = "OVERWRITE"
      service_account_role_arn = module.aws_ebs_csi_driver_irsa.iam_role_arn
    }
    coredns = {
      addon_version     = "v1.11.4-eksbuild.14"
      resolve_conflicts = "OVERWRITE"
    }
    kube-proxy = {
      addon_version     = "v1.32.6-eksbuild.2"
      resolve_conflicts = "OVERWRITE"
    }
    vpc-cni = {
      addon_version            = "v1.20.0-eksbuild.1"
      resolve_conflicts        = "OVERWRITE"
      service_account_role_arn = module.vpc_cni_irsa.iam_role_arn
    }
  }

  tags = local.tags
}

module "eks_aws_auth" {
  source  = "terraform-aws-modules/eks/aws//modules/aws-auth"
  version = "20.37.2"

  create_aws_auth_configmap = true
  manage_aws_auth_configmap = true

  aws_auth_roles = var.aws_auth_roles
  aws_auth_users = var.aws_auth_users
}

module "karpenter" {
  source  = "terraform-aws-modules/eks/aws//modules/karpenter"
  version = "20.35.0"

  cluster_name                    = module.eks.cluster_name
  irsa_oidc_provider_arn          = module.eks.oidc_provider_arn
  enable_spot_termination         = false
  enable_irsa                     = true
  irsa_namespace_service_accounts = ["karpenter:karpenter"]

  create_pod_identity_association = false
  enable_pod_identity             = true

  node_iam_role_additional_policies = {
    AmazonSSMManagedInstanceCore = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  }

  tags = local.tags
}
