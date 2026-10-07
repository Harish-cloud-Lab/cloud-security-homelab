Goal:  Create a workflow that runs Checkov (on Terraform and Dockerfile) and Trivy (on the image) every time you push code. A failing check shows a red X on GitHub, a passing one shows a green tick.

Github looks for workflows in only one exact folder. So I created that by following commands in powershell.

mkdir .github/workflows

and the security scan file inside workflow folder.

mkdir .github/workflows.security-scan.yml

In the security scan file i pasted some code having 2 jobs, the first one is Checkov(Which scans terraform and Dockerfile) and another one is Trivy (Builds image and scan it).

Then i pushed that code to github using git commands:
git add .
git commit -m "Day 6: Add Github Actions security pipeline."
git push

After pushing it to github, i went to github Actions tab where i found workflow "Day 6: "Add Github Actions security pipeline." I clicked on it to check Job Checks.
So when i entered inside this workflow i found 2 Jobs were running but shown red sign(Means Failed) after some time.
I checked the errors given by Checkov tool : Errors were related to access logging and security groups.
Later, i went into terraform file and made some changes by adding checkov skip comments wherever needed.Those skip comment are written as:

#checkov:skip=CKV_AWS_18: This is the log destination, logging it would create an endless chain of buckets. (This comment added in aws_s3_bucket_log_target resource )
#checkov:skip=CKV2_AWS_5: Scan-only lab file, no instance uses this group yet.(This comment is added in aws_security_group resource)

Adding these two skip comments and pushing workflow file (Day 6: Add log bucket and document accepted findings.) to github solved errors given by checkov tool. 
Now I went to fix error given by Trivy tool. The error arose due to case sensitive letters of a file which i changed/renamed by following commands:

git mv Docker docker_tmp
git mv docker_tmp docker

and then i checked status by:     Git status
Again I pushed new and completed workflow on github (Day 6: Fixed Docker Folder name case.) and checked the result in the Actions tab.

I got green signal showing all checks passed.
