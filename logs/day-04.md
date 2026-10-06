On the day 4 I used Trivy tool to check for vulnerabilities on nginx server.
For that i started one container using following command.

docker run --rm -d -p 8080:80 --name web nginx:1.21, 

And then on the browser i opened nginx using url http://localhost:8080
I picked older version of nginx because older versions has some known vulnerabilities.
Then i have given following command to powershell to check for vulnerabilities on nginx 1.21 

docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image nginx:1.21

docker run --rm aquasec/trivy image nginx:1.21

As an output powershell had shown total 921 vulnerabilities with all severity levels.
After that i sorted only those vulnerabilities which High or Critical Severity.

Command: docker run --rm aquasec/trivy image --severity HIGH,CRITICAL nginx:1.21

This command sorted vulnerabilities based on given severity and shown 256 vulnerabilities.
Then I upgraded the nginx image to stable alpine 3.24.2

Command: docker run --rm aquasec/trivy image --severity HIGH,CRITICAL nginx:stable-alpine

As alpine based are smaller so it has less vulnerabilities in it, so i got only 2 vulnerabilities.


