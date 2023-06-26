output "client_id" {
    description = "ClientID of UserPool Client"

    value = aws_cognito_user_pool_client.client.id
}

output "userpool_id" {
    description = "UserPoolID of UserPool"

    value = aws_cognito_user_pool.ctf_pool.id
}

output "identitypool_id" {
    description = "IdentityPoolID of IdentityPool"

    value = aws_cognito_identity_pool.ctf_identity_pool.id
}

output "region" {
    value = var.region
}

output "mod_role" {
    value = var.role_name
}

output "flag_function_name" {
    description = "Name of the Lambda function with the Flag"

    value = aws_lambda_function.flag_lambda.function_name
}

output "api_gateway_url_root" {
    description = "URL for apigateway"

    value = aws_api_gateway_stage.apigw_stage.invoke_url
}

output "api_gateway_url_login" {
    description = "URL for apigateway"

    value = "${aws_api_gateway_stage.apigw_stage.invoke_url}/login"
}

output "api_gateway_url_loggedin" {
    description = "URL for apigateway"

    value = "${aws_api_gateway_stage.apigw_stage.invoke_url}/home"
}

output "api_gateway_url_moderator" {
    description = "URL for apigateway"

    value = "${aws_api_gateway_stage.apigw_stage.invoke_url}/mods"
}

output "api_gateway_url_flag" {
    description = "URL for apigateway"

    value = "${aws_api_gateway_stage.apigw_stage.invoke_url}/flag"
}