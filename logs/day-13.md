**S3 Audit Script.**
# Shifted docker to another drive
# Wazuh deployment postponed. (It took more place and my system got problems.)
# saved only required requirements in requirements.txt


**Goal:** Building an auditor that checks every bucket for three problems (Public Access, Encryption and Versioning) and giving each finding a severity and also printing summary.
# for that i created three buckets which has one mentioned problem to each bucket .
# so auditor will catch them.

**Started Moto Server**
       moto_server -p 4566

**Test Environment**
    <dir-name>/.venv/Scripts/Activate.ps1     // Activates Virtual Environment
    $env:AWS_ACCESS_KEY_ID="<id>"
    $env:AWS_SECRET_ACCESS_KEY="<password>"
    $env:AWS_DEFAULT_REGION="<Region>"

**Code**
    Written code file that created three buckets with different configurations. (Good Bucket, Weak Bucket and Partial Bucket)
    code <dir-name>/<file-name>.py
    python <dir-name>/<file-name>.py

 
**Auditor**
    I had written code to audit those 3 buckets.
    code <dir-name>/<file-name>.py

**Audit Findings**
    When executed code,
               HIGH    weak-bucket      public-access-block  No public access block configured
               MEDIUM  weak-bucket      encryption           No default encryption configured
               LOW     weak-bucket      versioning           Versioning is not enabled
               HIGH    partial-bucket   public-access-block  Public access block is incomplete
               MEDIUM  partial-bucket   encryption           No default encryption configured  
          Checked 3 Buckets 2 HIGH, 2 Medium, 1 Low

# Good Bucket stayed quite, weak and partial bucket shown issues.


    
