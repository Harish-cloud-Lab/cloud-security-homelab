**Deploying Terraform with Moto and verifying with Python**

Started Virtual Environment and Moto server.
      <dir-name>\.venv\Scripts\Activate.ps1
      moto_server -p 4566

Opened New Powershell window.
Created new directory for local root module
Added terraform code inside the file in that directory.

Created fake credentials in powershell 
      $env:AWS_ACCESS_KEY_ID=""
      $env:AWS_SECRET_KEY_ACCESS=""
      $env:AWS_DEFAULT_REGION=""

Inside newly created directory
    terraform init  **This command downloads AWS provider (Installs Hashicorp)**
    terraform plan  **This command shows what terraform would create.**
    terraform apply
Hashicorp is a provider that allows terraform to talk with moto server. (hashicorp downloaded because i declared that in my main file in local terraform directory.)
terraform plan : it checks what resources needs to be add in moto (fake AWS) and tells the exact number of resources needs to be added.
terraform apply : applies required number of resources to the moto.

**Python Checker code to find Bucket is risky or not.**

     python <dir-name>/<file-name2>.py
     
If every resource is present in moto so command will show OK.

**Removing Public_Access_Block from moto**
I removed public_access_block configuration from moto using command

       terraform destry -target="module.lab.aws_s3_bucket_public_access_block.logs

Then i again checked with **Python Checker** I got Risky as my output.

**Reapply terraform plan** inside the local directory.
         terraform plan   OR
         terraform apply   you can use it directly (It plans and applies required)

This time **Python checker** shown OK as my output.








