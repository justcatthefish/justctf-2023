#!/bin/bash

set -e

if [ -z "$1" ] 
then
    PROFILE="justctf"
else
    PROFILE=$1
fi

cd terraform
terraform init
terraform apply -auto-approve
terraform output > tf_output.txt
cd -
cd terraform/lambda/Flag2/package
zip -r ../deploy.zip .
cd -
cd terraform/lambda/Flag2
zip deploy.zip main.py
cd -
aws lambda publish-version --function-name FlagLambda --description "I should move the key outside of the function..." --profile $PROFILE
aws lambda update-function-code --function-name FlagLambda --zip-file fileb://terraform/lambda/Flag2/deploy.zip --profile $PROFILE
sleep 10
aws lambda update-function-configuration --function-name FlagLambda --description "Good that the new version doesn't have hardcoded keys anymore." --environment Variables={BUCKET_NAME=bucket-with-very-very-secret-secrets-jctf} --profile $PROFILE