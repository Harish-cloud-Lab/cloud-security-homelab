**Secret Scanning in Pipeline**
So on my day 7, I Scanned files and full git history for leaked secrets, add Gitledeaks to the pipeline, and cleaned up the repo.

First I scanned locally (in Powershell) by following command. where i got **no leaks found** message.

**docker run --rm -v ${PWD}:/repo zricethezav/gitleaks:latest detect --source /repo -v**

**Adding Gitleaks job in .yml file**
I added gitleaks job code inside that .yml file.

**Strengthened  .gitignore**
I added following lines at he bottom of .gitignore to block most common accidential leaks.

.env
*.pem
*.key
*.tar
credentials
.aws/


**Pushed on Github**
I pushed that on github where i got error showing **Invalid workflow file**
I was sure that the error arose because i entered gitleaks job code after exit code: 1 (part of trivy image).

**But I forgot that YAML files are strict about spaces**
**Checkov and Trivy jobs were at two spaces from left and I added .gitleaks job three spaces from left**

I fixed that spacing issue and saved that file.

**Code Pushed again on Github**
After pushing corrected code on github, I checked Actions tab where i found that all three jobs were passed.


