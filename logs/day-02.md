Firstly, I cloned github repo in powershell directory(cloud-security-homelab), Then i checked contents inside the directory.
Where i found terraform directory i went inside that terraform directory.
where i used <code> command with main.th as my file name and then VS code's code window opened where i pasted code and saved that file.
then i came outside from terraform directory to main directory(cloud-secuirty-homelab).
so now i have to scan that file to check errors, For that i used docker command.
<docker run --rm -v ${PWD}/terraform:/tf bridgecrew/checkov -d /tf>
this command helped me in scanning main.tf file which has s3 bucket code.
Note: Checkov is a open source tool for scanning IaC (Infrastructure as Code) for security and misconfigurations before you deploy application.
It Scans following.
Terraform (including plan files) and OpenTofu, 
CloudFormation and AWS SAM, 
Kubernetes manifests and Helm charts, 
Dockerfiles, 
ARM templates and Bicep (Azure), 
Serverless Framework, Ansible, and others, 
CI/CD configs such as GitHub Actions, GitLab CI, and CircleCI, 
Secrets in code, and vulnerable open-source dependencies (SCA).

After running checkov scan i got 8 Passed Checks, 10 Failed Checks and 0 Skipped Checks.
Checkov tool give ID for each check syntax: CKV_<Provider/Type>_<Number> example: CKV_AWS_18 
Note: checkov tool id's are already decided.
