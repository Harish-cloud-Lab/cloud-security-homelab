**Finding public S3 Buckets using Python script.**

**Goal**: Run Localstack, Create 2 test buckets (One protected, one not) and write a script that tells which is public or not.

**Installed Python 3.12 and Verified it.**
winget install --id Python.Python.3.12 -e
Python --version

**Entering Virtual Environment**
mkdir <dir-name>
cd <dir-name>
python -m venv .venv  **This creates virtual environment (.venv)**
.venv\Scripts\Activate.ps1  **This Activates virtual environment (.venv)** 

I got error while activating the virtual environment because of powershell's security setting that blocking me from running local file scripts.
To solve this I edited ExecutionPolicy

**Set-ExecutionPolicy -Scope CurrentUser RemoteSigned** This command changes powershell security settings to allow you to run local script files.

I again tried to activate Virtual Environment and i succeeded.
Verify: Your prompt will show (.venv) at the start.

Installation of boto3 (Official AWS SDK for Python, Into the virtual environment.) and moto_server.
**boto3**: Allows python scripts to talk with AWS Services like EC2,S3 and so on.
**moto_Server**: Moto is the fake AWS
Start moto server-   **moto_server -p 4566**

Exit the directory and make sure .venv still activate. (See at the start of the prompt).
cd ..

Adding .venv/ to .gitignore 
Add-Content .gitignore "/<dir-name/.venv/>"

**.gitignore**: Its a plain text file tells git which file or folders to skip. Anything listed in it wont be tracked, committed or pushed on Github.

.venv added to .gitignore because
   -> It Contains hundreds of library files (here, boto3 and everything it depend on)
   -> Its specific to my pc and wont work anywhere.
   -> It can recreated at any time from a list of requirements so no need to store it.

Starting **Localstack** through Docker
docker run --rm -d -p 4566:4566 --name localstack localstack/localstack

**Localstack**: 
      -> It is a tool that pretends to be AWS on computer.
      -> It runs as a docker container and offers fake versions of AWS services.
      -> you can build and test AWS code without an AWS account, without internet, and without paying anything.

**Note**: It requires Authorization token to use localstack without this it will show license activation failed error. (I used Hobby Version.)

**docker logs localstack --tail 5**  This command checks localstack status (Ready or Not).


**Creation of test Buckets and Credentials**

**Credentials**
    -> $env:AWS_ACCESS_KEY_ID=""
    -> $env:AWS_SECRET_ACCESS_KEY=""
    -> $env:AWS_DEFAULT_REGION=""

Note: localstack accepts any values. no need to give real credentials.

**Buckets Creation**
code /<dir-name>/<file-name>.py

Added code for one protected and another unprotected bucket.

**Run Python Code** : Created Safe Bucket and Risky Bucket.

**Checking Buckets**
Written code to check bucket safety.

code /<dir-name>/<file-name2>.py

**Run Python Code** 
 python /<dir-name>/<file-name2>.py

 Output:-
        -> OK   safe bucket
        -> RISKY    risky bucket (public access block missing or incomplete)
        -> Checked 2 buckets 1 risky.

**Important**
When i pushed my work on GitHub Actions Pipeline, My Pipeline went red so i further checked inside.
found that because newer vulnerabilities published with their fixes were already existed.
So, I read that table, patched the package in dockerfile  and verified the container run as non-root.
And the pipeline went green.









