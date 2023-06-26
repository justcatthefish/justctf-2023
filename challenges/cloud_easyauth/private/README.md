# EasyAuth

Fully automated build

### Prerequisites

* [Terraform](https://developer.hashicorp.com/terraform/tutorials/aws-get-started/install-cli)
* [awscli](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
* Configured AWS profile locally:
```bash
aws configure
# Need to set AWS Access Key, AWS Secret Access Key and region -> eu-west-1 recommended
# Use keys to IAM User with Administrator Access, NOT THE ROOT ACCOUNT
# Profile could be named using --profile flag, but by default script is using 'default' unnamed profile
```

## Run

Pray and click enter:
```bash
# By default script uses profile named justctf - but can be given another through positional argument
./build_and_run.sh [aws_profile_name]
```

## Delete

```bash
cd terraform
terraform destroy --auto-approve
# Destroys also every bucket, cloudwatch and cloudtrail, so whole logging history.
```

## WAF

I left WAF setup in terraform (lines 1154-1234 of terraform/main.tf) - feel free to delete them, that's the only thing which is outside of free tier. Other than that, whole challenge could run for free (at least for some time).

## "It doesn't work as intended, but behaves as expected" - small bug

During competition we saw a small bug - API Gateway Authorizer was caching response, and it was connected to all of the endpoints. Because of that, it was possible to access /flag and /mods without proper role (if you first accessed /home). Also if you tried to access /flag or /mods first, then it would cache the unathorized response (heh). If you want full CTF experience - just run this - but if you want to fix it, there is a hotpatch at 923 line of terraform/main.tf, just uncomment and it should work fine then (well, I didn't test it, but I really hope it would and it should).

### Why there is so many thrash!?

*./terraform/lambda/AuthorizerLibLayer* - this one has to be compiled by hand using docker. It's late, I don't want to script it :c Just compressed it.