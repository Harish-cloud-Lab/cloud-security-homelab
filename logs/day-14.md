**Security Groups, Policy and ACL checks.**

**Goal:**- Adding new checklist that checks Security Groups, Policies and Access Control Lists (ACls).

# Start Moto Server
      Before that activate virtual environment.
              <dir-name>/.venv/scripts/activate.ps1
      Start moto server
              moto_server -p 4566

Open new Powershell window and activate virtual environment there also.

# Bucket Creation
     code <dir-name>/<file-name2>.py     // created 4 things open-policy bucket, public acl bucket , risky-sg and web-sg
     python <dir-name>/<file-name2>.py

# Bucket Audit
      // on day 13 I have created one .py file to check only S3.
      // So, I added EC2 and few checks like Security Groups, Policies and ACLs.
      // I also changed the name of that file using git
              git mv example_s3.py example.py

  Python <dir-name>/<example>.py

# Findings
       8 High 4 Medium 3 Low 
       HIGH    open-policy-bucket public-access-block  No public access block configured
       HIGH    open-policy-bucket bucket-policy        Policy statement 'PublicRead' allows everyone
       HIGH    partial-bucket     public-access-block  Public access block is incomplete
       HIGH    public-acl-bucket  public-access-block  No public access block configured
       HIGH    public-acl-bucket  bucket-acl           ACL grants READ to AllUsers
       HIGH    risky-sg           sg-open-ingress      SSH (port 22) open to the internet
       HIGH    risky-sg           sg-open-ingress      MySQL (port 3306) open to the internet
       HIGH    weak-bucket        public-access-block  No public access block configured
       MEDIUM  open-policy-bucket encryption           No default encryption configured
       MEDIUM  partial-bucket     encryption           No default encryption configured
       MEDIUM  public-acl-bucket  encryption           No default encryption configured
       MEDIUM  weak-bucket        encryption           No default encryption configured
       LOW     open-policy-bucket versioning           Versioning is not enabled
       LOW     public-acl-bucket  versioning           Versioning is not enabled
       LOW     weak-bucket        versioning           Versioning is not enabled

# Error
    // when i pushed it on github my Actions tab turned Red.
    // When checked, i found out that Trivy image scan failed due to new vulnerabilities.
    // so i fixed those vulnerabilities through docker and application tested locally
    // local test shown 0 vulnerabilities.
    // then i again pushed on github and aftersome some time Actions tab turned green.



.
