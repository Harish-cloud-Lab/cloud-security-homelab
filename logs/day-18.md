**Cloud Detection, Correlation and Tests**

# Goal
    Adding 3 Cloud Detection Rules
    Correlations (It joints two signals. For eg.Login from IP address using Brute-Force and the same IP address changing cloud settings after login.) 
    Tests (code will detect cloud logs as well, runs the cloud correlation rules, counting lines which arent parsed.)

# Virtual Environment Activation

     <dir-name>/.venv/scripts/activate.ps1

# Cloud Detection Rules

     Rule 1. Will Check for cloud Public-Access-Block-Removed
     Rule 2. Will check for Cloud Bucket-Policy-Changed
     Rule 3. Will check for logging-Disabled

# Correlation

    Rule. Will check for the IP which logged in through Brute Force and then the same IP changed cloud settings.

# Detector

    Upgraded it to detect cloud logs as well as SSH logs, Run the cloud and Correlation rules, Count lines it cant parse.

# Ran Detector

    Ran Detector on two days of fake logs (Clean Day & Attack Day)
    On Clean Day it produced zero errors.
    On the Attack Day is produced six errors- the brute force, the successful login, the public access block removal, the policy change, the logging stop.
    And correlation- Cloud changes from an address that just logged in after a brute force - 3 cloud change(s) within 1800s of the login: cloud-logging-disabled, cloud-public-access-block-removed, cloud-bucket-policy-changed

# Automated Tests

    They cover clean day and attack day, each rule, two separate attackers, a login with too few failures, the correlation firing for the same address and not for the different one,
    Line Parsing, Unparesable lines being counted and unknown rule type error.


# Ran whole Test Suite.

    python -m pytest tests -q

    Got 26 passed results (11 Auditor tests and 15 todays tests)

# Pushed 


    
