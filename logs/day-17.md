**Detection & Response**

# Building Fake logs and Detecting them by define rules.

# Detection Directory
     mkdir <dir-name>

# Virtual Environment Activation
     <dir-name>/.venv/scripts/activate.ps1

# pyyaml python tool installation.   (pyyaml- Python's YAML Library)
     pip install pyyaml
  // added pyyaml to requirements.txt also.

# Fake Log Generator code file.
     code <dir-name>/<code-filename>.py

  // As my repo is public now, so i used IPs that allowed for documentation and usernames are made up.

# Clean day and Attack day Logs Generation

  // Clean Day- A set of logs from a period of time without malicious activity.

           python <dir-name>/<code-filename>.py --seed 1 --out <dir-name>/sample_logs/clean

           Output: Wrote 43 SSH Lines and 15 Cloud Events in sample_logs/clean

  // Attack Day- A set of logs include malicious activity.

            python <dir-name>/<code-filename>.py --attack --seed 1 --out <dir-name>/sample_logs/attack
  
            Output: Wrote 56 SSH Lines and 18 Cloud Events in sample_logs/attack

# Seeing Attack Logs
            Get-Content <dir-name>/sample.logs/attacks/auth.log | Select-String "203.0.113.50"

  // This command shown 12 outputs out of which 11 were failed login attempts by an attacker and 1 successful login attempt.


# Activity Detection from attack logs.
  // This indicates what suspicious looks like.
  // two detection rules .yml file
          1. SSH bruteforce
          2. Successful SSH Login after multiple failure attempts.
  
                 code <dir-name>/<dir-name>/<filename>.yml     
                 code <dir-name>/<dir-name>/<filename-2>.yml    

# Rules Detection using Python
  // Python code that detects suspicious activity in the log using rules.

                code <dir-name>/<detect-filename>.py
                python <dir-name>/<detect-filename>.py --auth <dir-name>/sample_logs/clean/auth.log  // Python try to find malicious activity using assigned rules in clean day log.
                echo $LASTEXITCODE              // if it prints 0 means success no errors found

                python <dir-name>/<detect-filename>.py --auth <dir-name>/sample_logs/attack/auth.log  // Python try to find malicious activity using assigned rules in attack day log.
                echo $LASTEXITCODE             // if it prints numbers like (1,4,121,7) means something failed or reported an problem.
 
 // echo $LASTEXITCODE prints the exit code of last ran command in powershell.


 # .gitignore
  // added /sample_logs/ to gitignore as logs can be recreated.



  
     
