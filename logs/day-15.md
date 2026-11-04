**A Proper Tool with a Report, Automated Tests, Continuous Integration**

# Goal: 
     Make some changes in code so code not only gives output but also creates report of it.
     Downloading pytest for Automated testing.
     Adding audit job in CI pipeline.


# Start virtual environment and moto server also start virtual environment in 2nd powershell window.
    <dir-name>/.venv/scripts/activate.ps1
    moto_server -p 4566

# Fake Credentials Set
    $env:AWS_ACCESS_KEY_ID=""
    $env:AWS_SECRET_ACCESS_KEY=""
    $env:AWS_DEFAULT_REGION=""

# Modify code from audit file and Run it.
    code <dir-name>/<audit-file-name>.py           // This  file checks fake AWS Environment
    python <dir-name>/<audit-file-name>.py

# Download Pytest for Automated Testing.
    pip install pytest
    mkdir <test-directory>
    code <test-directory>/<test-configuration-file>.py       //autouse=TRUE
    code <test-directory>/<audit-test-file>.py               // This file will check audit file that  i modified earlier. means Audit's audit.

# Run Pytest
    pytest -m <directory-name> -q

    Output: 11 Passed    [100%]

# Pytest in Continuous Integration 
    I have added Pytest Job in CI workflow file.    
    Pushed on Github

# README files for all 3 completed projects.
    // I create one project directory.
    // then created 3 different .md project files
    // Pushed it on Github.
    

    
     
