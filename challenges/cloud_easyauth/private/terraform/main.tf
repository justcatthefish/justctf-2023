terraform {
    required_providers {
      aws = {
        source  = "hashicorp/aws"
        version = "~> 4.0"
      }
      archive = {
        source  = "hashicorp/archive"
        version = "~> 2.2.0"
      }
    }
}

provider "aws" {
    region  = var.region
    profile = var.profile
    default_tags {
        tags = {
            "owner": "Kusik",
            "project": "justCTF"
        }
    }
}

data "aws_caller_identity" "current" {}

locals {
    timestamp = formatdate("YYYYMMDDhhmmss", timestamp())
}

################################## DynamoDB for PreSignup PoW ##################################

resource "aws_dynamodb_table" "PoW_table" {
    name            = "PoW-table"
    billing_mode    = "PROVISIONED"
    read_capacity   = 25
    write_capacity  = 25
    hash_key        = "username"

    attribute {
        name = "username"
        type = "S"
    }
}

################################## Lambda PreSignup ##################################

data "archive_file" "pre_signup" {
    type = "zip"

    source_dir  = "${path.module}/lambda/PreSignupLambda"
    output_path = "${path.module}/lambda/PreSignup.zip"
}

resource "aws_iam_role" "presignup_lambda_role" {
    name = "presignup_lambda_role"

    assume_role_policy = jsonencode({
        Version   = "2012-10-17"
        Statement = [
            {
                Effect  = "Allow"
                Action  = "sts:AssumeRole"
                Principal = {
                    Service = "lambda.amazonaws.com"
                }
            }
        ]
    })
}

resource "aws_iam_policy" "presignup_dynamodb_policy" {
    name        = "presignup_dynamodb_readwrite"
    path        = "/"
    description = "Policy for PreSignup Lambda to write and retrieve PoW challenges"

    policy = jsonencode({
        Version   = "2012-10-17"
        Statement = [
            {
                Effect  = "Allow"
                Action  = [
                    "dynamodb:PutItem",
                    "dynamodb:GetItem",
                    "dynamodb:Scan",
                    "dynamodb:Query",
                    "dynamodb:UpdateItem",
                    "dynamodb:DeleteItem"
                ]
                Resource = aws_dynamodb_table.PoW_table.arn
            }
        ]
    })
}

resource "aws_iam_role_policy_attachment" "lambda_basic_presignup" {
    role        = aws_iam_role.presignup_lambda_role.name
    policy_arn  = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "lambda_dynamodb_presignup" {
    role        = aws_iam_role.presignup_lambda_role.name
    policy_arn  = aws_iam_policy.presignup_dynamodb_policy.arn
}

resource "aws_lambda_function" "presignup_lambda" {
    function_name   = "PreSignupLambda"
    filename        = "${path.module}/lambda/PreSignup.zip"

    runtime     = "python3.10"
    handler     = "main.lambda_handler"
    memory_size = 256
    timeout     = 10

    source_code_hash = data.archive_file.pre_signup.output_base64sha256

    role = aws_iam_role.presignup_lambda_role.arn

    environment {
        variables = {
            TABLE_NAME = aws_dynamodb_table.PoW_table.name
            DIFFICULTY = var.challenge_difficulty
            PREFIX_LEN = var.prefix_length
            VALID_TIME = var.validity_time
        }
    }

    depends_on = [ 
        aws_iam_role_policy_attachment.lambda_basic_presignup,
        aws_iam_role_policy_attachment.lambda_dynamodb_presignup
     ]
}

resource "aws_cloudwatch_log_group" "presignup_log" {
    name = "/aws/lambda/${aws_lambda_function.presignup_lambda.function_name}"
    
    retention_in_days = 30
}

################################## Lambda PostSignup ##################################

data "archive_file" "post_signup" {
    type = "zip"

    source_dir  = "${path.module}/lambda/PostSignupLambda"
    output_path = "${path.module}/lambda/PostSignup.zip"
}

resource "aws_iam_role" "postsignup_lambda_role" {
    name = "postsignup_lambda_role"

    assume_role_policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
            {
                Effect  = "Allow"
                Action  = "sts:AssumeRole"
                Principal = {
                    Service = "lambda.amazonaws.com"
                }
            }
        ]
    })
}

resource "aws_iam_role_policy_attachment" "lambda_basic_postsignup" {
    role        = aws_iam_role.postsignup_lambda_role.name
    policy_arn  = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "lambda_cognito_postsignup" {
    role        = aws_iam_role.postsignup_lambda_role.name
    policy_arn  = "arn:aws:iam::aws:policy/AmazonCognitoPowerUser"
}

resource "aws_lambda_function" "postsignup_lambda" {
    function_name   = "PostSignupLambda"
    filename        = "${path.module}/lambda/PostSignup.zip"

    runtime     = "python3.10"
    handler     = "main.lambda_handler"
    memory_size = 256
    timeout     = 10

    source_code_hash = data.archive_file.post_signup.output_base64sha256

    role = aws_iam_role.postsignup_lambda_role.arn

    depends_on = [ 
        aws_iam_role_policy_attachment.lambda_basic_postsignup,
        aws_iam_role_policy_attachment.lambda_cognito_postsignup
     ]
}

resource "aws_cloudwatch_log_group" "postsignup_log" {
    name = "/aws/lambda/${aws_lambda_function.postsignup_lambda.function_name}"
    
    retention_in_days = 30
}

################################## Lambda Flag ##################################

resource "null_resource" "download_pip1_libraries" {
    provisioner "local-exec" {
        command = "pip3 install --target ${path.module}/lambda/Flag1 pycryptodome"
    }
}

resource "null_resource" "download_pip2_libraries" {
    provisioner "local-exec" {
        command = "pip3 install --target ${path.module}/lambda/Flag2/package pycryptodome"
    }
}

data "archive_file" "flag" {
    type = "zip"

    source_dir  = "${path.module}/lambda/Flag1"
    output_path = "${path.module}/lambda/Flag.zip"

    depends_on = [
        null_resource.download_pip1_libraries
    ]
}

resource "aws_iam_role" "flag_lambda_role" {
    name = "flag_lambda_role"

    assume_role_policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
            {
                Effect  = "Allow"
                Action  = "sts:AssumeRole"
                Principal = {
                    Service = "lambda.amazonaws.com"
                }
            }
        ]
    })
}

resource "aws_iam_policy" "flag_s3_policy" {
    name        = "flag_s3_read"
    path        = "/"
    description = "Policy for Flag Lambda to retrieve secrets"

    policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
            {
                Effect  = "Allow"
                Action  = [
                    "s3:ListBucket",
                    "s3:ListBucketVersions",
                    "s3:GetObject",
                    "s3:GetObjectVersion"
                ]
                Resource = [
                    aws_s3_bucket.secrets_bucket.arn,
                    "${aws_s3_bucket.secrets_bucket.arn}/*"
                ]
            }
        ]
    })
}

resource "aws_iam_role_policy_attachment" "lambda_basic_flag" {
    role        = aws_iam_role.flag_lambda_role.name
    policy_arn  = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "lambda_dynamodb_flag" {
    role        = aws_iam_role.flag_lambda_role.name
    policy_arn  = aws_iam_policy.flag_s3_policy.arn
}

resource "aws_lambda_function" "flag_lambda" {
    function_name   = "FlagLambda"
    filename        = "${path.module}/lambda/Flag.zip"

    runtime = "python3.10"
    handler = "main.lambda_handler"
    timeout = 5

    source_code_hash = data.archive_file.flag.output_base64sha256

    role = aws_iam_role.flag_lambda_role.arn

    environment {
        variables = {
            KEY = var.key
            NONCE = var.nonce
        }
    }

    depends_on = [ 
        aws_iam_role_policy_attachment.lambda_basic_flag,
        aws_iam_role_policy_attachment.lambda_dynamodb_flag
     ]
}

resource "aws_cloudwatch_log_group" "flag_log" {
    name = "/aws/lambda/${aws_lambda_function.flag_lambda.function_name}"
    
    retention_in_days = 30
}

################################## Cognito User Pool ##################################

resource "aws_cognito_user_pool" "ctf_pool" {
    name                        = "jctf_pool"
    alias_attributes            = ["preferred_username"]

    admin_create_user_config {
        allow_admin_create_user_only = false
    }

    password_policy {
        minimum_length      = 10
        require_lowercase   = true
        require_numbers     = true
        require_symbols     = true
        require_uppercase   = true
    }

    username_configuration {
      case_sensitive = true
    }

    schema {
        name                        = "proof_of_work"
        attribute_data_type         = "String"
        developer_only_attribute    = false
        mutable                     = false
        required                    = false

        string_attribute_constraints {
            min_length = 0
            max_length = 2048
        }
    }
    
    schema {
        name                        = "role"
        attribute_data_type         = "String"
        developer_only_attribute    = false
        mutable                     = true
        required                    = false

        string_attribute_constraints {
            min_length = 0
            max_length = 2048
        }
    }

    lambda_config {
        pre_sign_up         = aws_lambda_function.presignup_lambda.arn
        post_confirmation   = aws_lambda_function.postsignup_lambda.arn
    }
}

resource "aws_lambda_permission" "cognito_permission_presignup" {
    statement_id  = "AllowExecutionFromCognito"
    action        = "lambda:InvokeFunction"
    function_name = aws_lambda_function.presignup_lambda.function_name
    principal     = "cognito-idp.amazonaws.com"

    source_arn = aws_cognito_user_pool.ctf_pool.arn
}

resource "aws_lambda_permission" "cognito_permission_postsignup" {
    statement_id  = "AllowExecutionFromCognito"
    action        = "lambda:InvokeFunction"
    function_name = aws_lambda_function.postsignup_lambda.function_name
    principal     = "cognito-idp.amazonaws.com"

    source_arn = aws_cognito_user_pool.ctf_pool.arn
}

resource "aws_cognito_user_pool_client" "client" {
    name            = "ctf_client"
    user_pool_id    = aws_cognito_user_pool.ctf_pool.id

    explicit_auth_flows = [
        # "ALLOW_USER_PASSWORD_AUTH", # Only for testing
        "ALLOW_USER_SRP_AUTH",
        "ALLOW_REFRESH_TOKEN_AUTH"
    ]
}

################################## Cognito Identity Pool ##################################

resource "aws_cognito_identity_pool" "ctf_identity_pool" {
    identity_pool_name = "ctf_identity_pool"

    allow_unauthenticated_identities = true
    cognito_identity_providers {
        client_id       = aws_cognito_user_pool_client.client.id
        provider_name   = "cognito-idp.${var.region}.amazonaws.com/${aws_cognito_user_pool.ctf_pool.id}"
    }
}

resource "aws_cognito_identity_pool_roles_attachment" "role_mappings" {
    identity_pool_id = aws_cognito_identity_pool.ctf_identity_pool.id

    roles = {
        "authenticated"     = aws_iam_role.authenticated_cognito_role.arn
        "unauthenticated"   = aws_iam_role.unauthenticated_cognito_role.arn
    }

    role_mapping {
        identity_provider   = "cognito-idp.${var.region}.amazonaws.com/${aws_cognito_user_pool.ctf_pool.id}:${aws_cognito_user_pool_client.client.id}"
        type                = "Rules"

        ambiguous_role_resolution = "AuthenticatedRole"

        mapping_rule {
            claim       = "custom:role"
            match_type  = "Equals"
            value       = "default_role"
            role_arn    = aws_iam_role.authenticated_cognito_role.arn
        }

        mapping_rule {
            claim       = "custom:role"
            match_type  = "Equals"
            value       = var.role_name
            role_arn    = aws_iam_role.moderator_cognito_role.arn
        }
    }
}

################################## IAM Unauthenticated ##################################

resource "aws_iam_role" "unauthenticated_cognito_role" {
    name        = "unauthenticated_bucket_listing_role"
    description = "Role for unauthenticated users, can list S3 buckets"

    assume_role_policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
            {
                Effect  = "Allow"
                Action  = "sts:AssumeRoleWithWebIdentity"
                Principal = {
                    Federated = "cognito-identity.amazonaws.com"
                }
                Condition = {
                    "StringEquals" = {
                        "cognito-identity.amazonaws.com:aud" = aws_cognito_identity_pool.ctf_identity_pool.id
                    }
                    "ForAnyValue:StringLike" = {
                        "cognito-identity.amazonaws.com:amr" = "unauthenticated"
                    }
                }
            }
        ]
    })
}

resource "aws_iam_role_policy" "unauthenticated_cognito_policy" {
    name = "unauthenticated_cognito_policy"
    role = aws_iam_role.unauthenticated_cognito_role.id

    policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
        {
            Effect = "Allow"
            Action = [
                "iam:GetRolePolicy"
            ]
            Resource = aws_iam_role.unauthenticated_cognito_role.arn
        },
        {
            Effect = "Allow"
            Action = [
                "s3:ListAllMyBuckets"
            ]
            Resource = "*"
        }
        ]
    })
}

################################## IAM Authenticated / Default ##################################

resource "aws_iam_role" "authenticated_cognito_role" {
    name        = "authenticated_better_bucket_listing_role"
    description = "Role for authenticated users with role default_user, can list S3 buckets and access some of them."

    assume_role_policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
            {
                Effect  = "Allow"
                Action  = "sts:AssumeRoleWithWebIdentity"
                Principal = {
                    Federated = "cognito-identity.amazonaws.com"
                }
                Condition = {
                    "StringEquals" = {
                        "cognito-identity.amazonaws.com:aud" = aws_cognito_identity_pool.ctf_identity_pool.id
                    }
                    "ForAnyValue:StringLike" = {
                        "cognito-identity.amazonaws.com:amr" = "authenticated"
                    }
                }
            }
        ]
    })
}

resource "aws_iam_role_policy" "authenticated_cognito_policy" {
    name = "unauthenticated_cognito_policy"
    role = aws_iam_role.authenticated_cognito_role.id

    policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
        {
            Effect = "Allow"
            Action = [
                "iam:GetRolePolicy"
            ]
            Resource = aws_iam_role.authenticated_cognito_role.arn
        },
        {
            Effect = "Allow"
            Action = [
                "s3:ListAllMyBuckets"
            ]
            Resource = "*"
        },
        {
            Effect = "Allow"
            Action  = [
                    "s3:ListBucket",
                    "s3:ListBucketVersions",
                    "s3:GetObject",
                    "s3:GetObjectVersion"
                ]
            Resource = [
                aws_s3_bucket.flag_bucket.arn,
                "${aws_s3_bucket.flag_bucket.arn}/*",
            ]
        }
        ]
    })
}

################################## IAM Moderator ##################################

resource "aws_iam_role" "moderator_cognito_role" {
    name        = "moderator_cognito_role"
    description = "Role for authenticated users with role ${var.role_name}, can do few more things."

    assume_role_policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
            {
                Effect  = "Allow"
                Action  = "sts:AssumeRoleWithWebIdentity"
                Principal = {
                    Federated = "cognito-identity.amazonaws.com"
                }
                Condition = {
                    "StringEquals" = {
                        "cognito-identity.amazonaws.com:aud" = aws_cognito_identity_pool.ctf_identity_pool.id
                    }
                    "ForAnyValue:StringLike" = {
                        "cognito-identity.amazonaws.com:amr" = "authenticated"
                    }
                }
            }
        ]
    })
}

resource "aws_iam_role_policy" "moderator_cognito_policy" {
    name = "moderator_cognito_policy"
    role = aws_iam_role.moderator_cognito_role.id

    policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
        {
            Effect = "Allow"
            Action = [
                "iam:GetRolePolicy"
            ]
            Resource = aws_iam_role.moderator_cognito_role.arn
        },
        {
            Effect = "Allow"
            Action = [
                "s3:ListAllMyBuckets",
                "lambda:ListVersionsByFunction",
                "lambda:ListFunctions",
                "lambda:GetFunction"
            ]
            Resource = "*"
        },
        {
            Effect = "Allow"
            Action  = [
                    "s3:ListBucket",
                    "s3:ListBucketVersions",
                    "s3:GetObject",
                    "s3:GetObjectVersion"
                ]
            Resource = [
                aws_s3_bucket.special_bucket.arn,
                "${aws_s3_bucket.special_bucket.arn}/*",
            ]
        }
        ]
    })
}

################################## S3 Buckets ##################################

resource "random_string" "r1" {
    length  = 8
    special = false
    upper   = false
}

resource "aws_s3_bucket" "flag_bucket" {
    bucket          = "flag-decrypted-${random_string.r1.result}"
    force_destroy   = true
}

resource "aws_s3_object" "flag" {
    bucket  = aws_s3_bucket.flag_bucket.id
    key     = "flag"
    source  = "${path.module}/s3/flag.txt"
}

resource "aws_s3_bucket" "special_bucket" {
    bucket          = "only-for-moderators-${random_string.r1.result}"
    force_destroy   = true
}

resource "aws_s3_object" "special_object" {
    bucket  = aws_s3_bucket.special_bucket.id
    key     = "jctf"
    source  = "${path.module}/s3/justcatthefish.txt"
}

resource "null_resource" "write_to_secrets" {
    provisioner "local-exec" {
        command = "echo -n ${var.flag} > ${path.module}/s3/secrets/flag && echo -n ${var.key} > ${path.module}/s3/secrets/key && echo -n ${var.nonce} > ${path.module}/s3/secrets/nonce"
    }
}

resource "aws_s3_bucket" "secrets_bucket" {
    bucket          = "bucket-with-very-very-secret-secrets-jctf"
    force_destroy   = true

    depends_on = [
        null_resource.write_to_secrets
    ]
}

resource "aws_s3_object" "secrets" {
    for_each    = fileset("${path.module}/s3/secrets/", "*")
    bucket      = aws_s3_bucket.secrets_bucket.id
    key         = each.value
    source      = "${path.module}/s3/secrets/${each.value}"

    depends_on = [
        null_resource.write_to_secrets
    ]
}

################################## Lambda Front ##################################

data "archive_file" "loggedin_page" {
    type = "zip"

    source_dir  = "${path.module}/lambda/LoggedInPage"
    output_path = "${path.module}/lambda/LoggedInPage.zip"
}

data "archive_file" "login_page" {
    type = "zip"

    source_dir  = "${path.module}/lambda/LoginPage"
    output_path = "${path.module}/lambda/LoginPage.zip"
}

data "archive_file" "moderator_page" {
    type = "zip"

    source_dir  = "${path.module}/lambda/ModeratorPage"
    output_path = "${path.module}/lambda/ModeratorPage.zip"
}

resource "aws_iam_role" "basic_lambda_role" {
    name = "basic_lambda_role"

    assume_role_policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
            {
                Effect  = "Allow"
                Action  = "sts:AssumeRole"
                Principal = {
                    Service = "lambda.amazonaws.com"
                }
            }
        ]
    })
}

resource "aws_iam_role_policy_attachment" "lambda_basic_frontend" {
    role        = aws_iam_role.basic_lambda_role.name
    policy_arn  = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_lambda_function" "loggedin_lambda" {
    function_name   = "LoggedInLambda"
    filename        = "${path.module}/lambda/LoggedInPage.zip"

    runtime = "python3.10"
    handler = "main.lambda_handler"
    timeout = 10

    source_code_hash = data.archive_file.loggedin_page.output_base64sha256

    role = aws_iam_role.basic_lambda_role.arn

    environment {
        variables = {
            ROLE_NAME = var.role_name
        }
    }

    depends_on = [ 
        aws_iam_role_policy_attachment.lambda_basic_frontend
    ]
}

resource "aws_cloudwatch_log_group" "loggedin_log" {
    name = "/aws/lambda/${aws_lambda_function.loggedin_lambda.function_name}"
    
    retention_in_days = 30
}

resource "aws_lambda_function" "login_lambda" {
    function_name   = "LoginLambda"
    filename        = "${path.module}/lambda/LoginPage.zip"

    runtime = "python3.10"
    handler = "main.lambda_handler"
    timeout = 5

    source_code_hash = data.archive_file.login_page.output_base64sha256

    role = aws_iam_role.basic_lambda_role.arn

    environment {
        variables = {
            USER_POOL_ID = aws_cognito_user_pool.ctf_pool.id
            IDENTITY_POOL_ID = aws_cognito_identity_pool.ctf_identity_pool.id
            CLIENT_ID = aws_cognito_user_pool_client.client.id
        }
    }

    depends_on = [ 
        aws_iam_role_policy_attachment.lambda_basic_frontend
     ]
}

resource "aws_cloudwatch_log_group" "login_log" {
    name = "/aws/lambda/${aws_lambda_function.login_lambda.function_name}"
    
    retention_in_days = 30
}

resource "aws_lambda_function" "moderator_lambda" {
    function_name   = "ModeratorLambda"
    filename        = "${path.module}/lambda/ModeratorPage.zip"

    runtime = "python3.10"
    handler = "main.lambda_handler"
    timeout = 10

    source_code_hash = data.archive_file.moderator_page.output_base64sha256

    role = aws_iam_role.basic_lambda_role.arn

    depends_on = [ 
        aws_iam_role_policy_attachment.lambda_basic_frontend
     ]
}

resource "aws_cloudwatch_log_group" "moderator_log" {
    name = "/aws/lambda/${aws_lambda_function.moderator_lambda.function_name}"
    
    retention_in_days = 30
}

################################## Lambda Authorizer ##################################

resource "null_resource" "unpack_layer" {
    provisioner "local-exec" {
        command = "tar -xf ${path.module}/lambda/AuthorizerLibLayer/crypto_layer.tar.gz -C ${path.module}/lambda/AuthorizerLibLayer"
    }
}

data "archive_file" "authorizer_layer" {
    type = "zip"

    source_dir  = "${path.module}/lambda/AuthorizerLibLayer"
    output_path = "${path.module}/lambda/AuthorizerLibLayer.zip"

    depends_on = [ 
        null_resource.unpack_layer
    ]
}

resource "aws_lambda_layer_version" "authorizer_lambda_layer" {
    filename    = "${path.module}/lambda/AuthorizerLibLayer.zip" 
    layer_name  = "authorizer_lambda_layer"

    compatible_runtimes = [
        "python3.10"
    ]

    depends_on = [ 
        data.archive_file.authorizer_layer
    ]
}

data "archive_file" "authorizer_file" {
    type = "zip"

    source_dir  = "${path.module}/lambda/Authorizer"
    output_path = "${path.module}/lambda/Authorizer.zip"
}

resource "aws_lambda_function" "authorizer_lambda" {
    function_name   = "AuthorizerLambda"
    filename        = "${path.module}/lambda/Authorizer.zip"

    runtime = "python3.10"
    handler = "main.lambda_handler"
    timeout = 15

    source_code_hash = data.archive_file.authorizer_file.output_base64sha256

    role = aws_iam_role.basic_lambda_role.arn

    layers = [
        aws_lambda_layer_version.authorizer_lambda_layer.arn
    ]

    environment {
        variables = {
            REGION = var.region
            USER_POOL_ID = aws_cognito_user_pool.ctf_pool.id
            MOD_ROLE = var.role_name
        }
    }

    depends_on = [ 
        aws_iam_role_policy_attachment.lambda_basic_frontend
    ]
}

resource "aws_cloudwatch_log_group" "authorizer_log" {
    name = "/aws/lambda/${aws_lambda_function.authorizer_lambda.function_name}"
    
    retention_in_days = 30
}

################################## API Gateway ##################################

resource "aws_api_gateway_rest_api" "apigw" {
    name = "ctf_lambda_apigw"

    endpoint_configuration {
      types = ["REGIONAL"]
    }
}

resource "aws_api_gateway_deployment" "apigw_ctf_deploy" {
    rest_api_id = aws_api_gateway_rest_api.apigw.id

    lifecycle {
        create_before_destroy = true
    }

    depends_on = [ 
        aws_api_gateway_method.apigw_method_flag,
        aws_api_gateway_method.apigw_method_loggedin,
        aws_api_gateway_method.apigw_method_login,
        aws_api_gateway_method.apigw_method_moderator,
        aws_api_gateway_integration.apigw_login_integration,
        aws_api_gateway_integration.apigw_loggedin_integration,
        aws_api_gateway_integration.apigw_flag_integration,
        aws_api_gateway_integration.apigw_moderator_integration
    ]
}

resource "aws_api_gateway_stage" "apigw_stage" {
    deployment_id   = aws_api_gateway_deployment.apigw_ctf_deploy.id
    rest_api_id     = aws_api_gateway_rest_api.apigw.id
    stage_name      = "ctf"
}

resource "aws_api_gateway_authorizer" "apigw_authorizer" {
    name = "cognito_loggedin_authorizer"
    type = "REQUEST"

    authorizer_uri  = aws_lambda_function.authorizer_lambda.invoke_arn
    rest_api_id     = aws_api_gateway_rest_api.apigw.id
    identity_source = "method.request.header.Authorization"

    #authorizer_result_ttl_in_seconds = 0

    authorizer_credentials = aws_iam_role.invocation_role.arn
}

resource "aws_iam_role" "invocation_role" {
  name = "api_gateway_auth_invocation"

  assume_role_policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
            {
                Effect  = "Allow"
                Action  = "sts:AssumeRole"
                Principal = {
                    Service = "apigateway.amazonaws.com"
                }
            }
        ]
    })
}

resource "aws_iam_role_policy" "invocation_policy" {
    name = "api_gateway_invocation"
    role = aws_iam_role.invocation_role.id

    policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
            {
                Effect = "Allow"
                Action = [
                    "lambda:InvokeFunction"
                ]
                Resource = aws_lambda_function.authorizer_lambda.arn
            }
        ]
    })
}

resource "aws_api_gateway_resource" "apigw_loggedin" {
    rest_api_id = aws_api_gateway_rest_api.apigw.id
    parent_id   = aws_api_gateway_rest_api.apigw.root_resource_id
    path_part   = "home"
}

resource "aws_api_gateway_method" "apigw_method_loggedin" {
    rest_api_id     = aws_api_gateway_rest_api.apigw.id
    resource_id     = aws_api_gateway_resource.apigw_loggedin.id
    http_method     = "GET"
    authorization   = "CUSTOM"
    authorizer_id   = aws_api_gateway_authorizer.apigw_authorizer.id
}

resource "aws_api_gateway_integration" "apigw_loggedin_integration" {
    rest_api_id             = aws_api_gateway_rest_api.apigw.id
    resource_id             = aws_api_gateway_resource.apigw_loggedin.id
    http_method             = aws_api_gateway_method.apigw_method_loggedin.http_method
    integration_http_method = "POST"
    type                    = "AWS_PROXY"
    uri                     = aws_lambda_function.loggedin_lambda.invoke_arn
}

resource "aws_api_gateway_resource" "apigw_login" {
    rest_api_id = aws_api_gateway_rest_api.apigw.id
    parent_id   = aws_api_gateway_rest_api.apigw.root_resource_id
    path_part   = "login"
}

resource "aws_api_gateway_method" "apigw_method_login" {
    rest_api_id     = aws_api_gateway_rest_api.apigw.id
    resource_id     = aws_api_gateway_resource.apigw_login.id
    http_method     = "GET"
    authorization   = "None"
}

resource "aws_api_gateway_integration" "apigw_login_integration" {
    rest_api_id             = aws_api_gateway_rest_api.apigw.id
    resource_id             = aws_api_gateway_resource.apigw_login.id
    http_method             = aws_api_gateway_method.apigw_method_login.http_method
    integration_http_method = "POST"
    type                    = "AWS_PROXY"
    uri                     = aws_lambda_function.login_lambda.invoke_arn
}

resource "aws_api_gateway_resource" "apigw_moderator" {
    rest_api_id = aws_api_gateway_rest_api.apigw.id
    parent_id   = aws_api_gateway_rest_api.apigw.root_resource_id
    path_part   = "mods"
}

resource "aws_api_gateway_method" "apigw_method_moderator" {
    rest_api_id     = aws_api_gateway_rest_api.apigw.id
    resource_id     = aws_api_gateway_resource.apigw_moderator.id
    http_method     = "GET"
    authorization   = "CUSTOM"
    authorizer_id   = aws_api_gateway_authorizer.apigw_authorizer.id
}

resource "aws_api_gateway_integration" "apigw_moderator_integration" {
    rest_api_id             = aws_api_gateway_rest_api.apigw.id
    resource_id             = aws_api_gateway_resource.apigw_moderator.id
    http_method             = aws_api_gateway_method.apigw_method_moderator.http_method
    integration_http_method = "POST"
    type                    = "AWS_PROXY"
    uri                     = aws_lambda_function.moderator_lambda.invoke_arn
}

resource "aws_api_gateway_resource" "apigw_flag" {
    rest_api_id = aws_api_gateway_rest_api.apigw.id
    parent_id   = aws_api_gateway_rest_api.apigw.root_resource_id
    path_part   = "flag"
}

resource "aws_api_gateway_method" "apigw_method_flag" {
    rest_api_id     = aws_api_gateway_rest_api.apigw.id
    resource_id     = aws_api_gateway_resource.apigw_flag.id
    http_method     = "GET"
    authorization   = "CUSTOM"
    authorizer_id   = aws_api_gateway_authorizer.apigw_authorizer.id
}

resource "aws_api_gateway_integration" "apigw_flag_integration" {
    rest_api_id             = aws_api_gateway_rest_api.apigw.id
    resource_id             = aws_api_gateway_resource.apigw_flag.id
    http_method             = aws_api_gateway_method.apigw_method_flag.http_method
    integration_http_method = "POST"
    type                    = "AWS_PROXY"
    uri                     = aws_lambda_function.flag_lambda.invoke_arn
}

resource "aws_lambda_permission" "apigw_permission_loggedin" {
    statement_id  = "AllowExecutionFromAPIGateway"
    action        = "lambda:InvokeFunction"
    function_name = aws_lambda_function.loggedin_lambda.function_name
    principal     = "apigateway.amazonaws.com"

    source_arn = "arn:aws:execute-api:${var.region}:${data.aws_caller_identity.current.account_id}:${aws_api_gateway_rest_api.apigw.id}/*/${aws_api_gateway_method.apigw_method_loggedin.http_method}${aws_api_gateway_resource.apigw_loggedin.path}"
}

resource "aws_lambda_permission" "apigw_permission_login" {
    statement_id  = "AllowExecutionFromAPIGateway"
    action        = "lambda:InvokeFunction"
    function_name = aws_lambda_function.login_lambda.function_name
    principal     = "apigateway.amazonaws.com"

    source_arn = "arn:aws:execute-api:${var.region}:${data.aws_caller_identity.current.account_id}:${aws_api_gateway_rest_api.apigw.id}/*/${aws_api_gateway_method.apigw_method_login.http_method}${aws_api_gateway_resource.apigw_login.path}"
}

resource "aws_lambda_permission" "apigw_permission_moderator" {
    statement_id  = "AllowExecutionFromAPIGateway"
    action        = "lambda:InvokeFunction"
    function_name = aws_lambda_function.moderator_lambda.function_name
    principal     = "apigateway.amazonaws.com"

    source_arn = "arn:aws:execute-api:${var.region}:${data.aws_caller_identity.current.account_id}:${aws_api_gateway_rest_api.apigw.id}/*/${aws_api_gateway_method.apigw_method_moderator.http_method}${aws_api_gateway_resource.apigw_moderator.path}"
}

resource "aws_lambda_permission" "apigw_permission_flag" {
    statement_id  = "AllowExecutionFromAPIGateway"
    action        = "lambda:InvokeFunction"
    function_name = aws_lambda_function.flag_lambda.function_name
    principal     = "apigateway.amazonaws.com"

    source_arn = "arn:aws:execute-api:${var.region}:${data.aws_caller_identity.current.account_id}:${aws_api_gateway_rest_api.apigw.id}/*/${aws_api_gateway_method.apigw_method_flag.http_method}${aws_api_gateway_resource.apigw_flag.path}"
}

################################## CloudTrail ##################################

resource "aws_cloudtrail" "cloudtrail" {
    name                            = "main_trail"
    s3_bucket_name                  = aws_s3_bucket.trail_bucket.id
    include_global_service_events   = true
    is_multi_region_trail           = true

    depends_on = [ 
        aws_s3_bucket_policy.trail_bucket_policy
    ]
}

resource "aws_s3_bucket" "trail_bucket" {
    bucket          = "trail-bucket-${random_string.r1.result}"
    force_destroy   = true
}

data "aws_iam_policy_document" "bucket_policy_for_cloudtrail_bucket" {
    statement {
        actions = [
            "s3:GetBucketAcl"
        ]
        effect = "Allow"
        resources = [ aws_s3_bucket.trail_bucket.arn ]
        principals {
            type = "Service"
            identifiers = [ "cloudtrail.amazonaws.com" ]
        }
    }
    statement {
        actions = [
            "s3:PutObject"
        ]
        effect = "Allow"
        resources = [ "${aws_s3_bucket.trail_bucket.arn}/*" ]
        principals {
            type = "Service"
            identifiers = [ "cloudtrail.amazonaws.com" ]
        }
        condition {
            test = "StringEquals"
            variable = "s3:x-amz-acl"
            values = [ "bucket-owner-full-control" ]
        }
    }
}

resource "aws_s3_bucket_public_access_block" "block_public_access_cloudtrail" {
    bucket = aws_s3_bucket.trail_bucket.id

    block_public_acls       = true
    block_public_policy     = true
    ignore_public_acls      = true
    restrict_public_buckets = true

    depends_on = [ 
        aws_s3_bucket_policy.trail_bucket_policy
    ]
}

resource "aws_s3_bucket_policy" "trail_bucket_policy" {
    bucket = aws_s3_bucket.trail_bucket.id
    policy = data.aws_iam_policy_document.bucket_policy_for_cloudtrail_bucket.json
}

################################## (Optional) AWS WAF ##################################

resource "aws_wafv2_web_acl" "waf" {
    name        = "CognitoWAF"
    description = "WAF for Cognito User Pool"
    scope       = "REGIONAL"

    default_action {
        block {}
    }

    visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name = "aws-ctf-waf-friendly-metric-name"
        sampled_requests_enabled = true
    }

    rule {
        name        = "RateLimit"
        priority    = 1

        action {
            block {}
        }

        statement {
            rate_based_statement {
                limit               = var.waf_limit
                aggregate_key_type  = "IP"
            }
        }

        visibility_config {
            cloudwatch_metrics_enabled  = true
            metric_name                 = "RateLimitMetric"
            sampled_requests_enabled    = true
        }
    }

    rule {
        name        = "AllowListingBeforeCTF"
        priority    = 0

        action {
            allow {}
        }

        statement {
            ip_set_reference_statement {
                arn = aws_wafv2_ip_set.allowlist.arn
            }
        }

        visibility_config {
            cloudwatch_metrics_enabled   = true
            metric_name                 = "RateLimitMetric"
            sampled_requests_enabled    = true
        }
    }
}

resource "aws_wafv2_ip_set" "allowlist" {
    name                = "AllowListBeforeCTF"
    description         = "AllowList of IPs which could access resources before CTF"
    scope               = "REGIONAL"
    ip_address_version  = "IPV4"
    
    addresses = [
        "83.27.55.95/32"
    ]
}

resource "aws_wafv2_web_acl_association" "waf_cognito_assoc" {
    resource_arn    = aws_cognito_user_pool.ctf_pool.arn
    web_acl_arn     = aws_wafv2_web_acl.waf.arn
}

resource "aws_wafv2_web_acl_association" "waf_apigw_assoc" {
    resource_arn    = aws_api_gateway_stage.apigw_stage.arn
    web_acl_arn     = aws_wafv2_web_acl.waf.arn
}