On the fifth day i built my own Docker Image and tried to secure it.
For that i created one directory and named it as Docker thereafter i written html code by creating a file (index.html) in docker directory.
Also i created one Dockerfile (without extension) inside that directory where i wrote some instructions.

FROM nginx:1.21
COPY index.html /usr/share/nginx/html/index.html


Then i scanned Dockerfile with two tools Trivy and Checkov.
When scanned with Trivy it shown 27 tests done out of which 25 passed and 2 failed
Failed Checks : 1. Specify at least one command in Dockerfile with non-root as user agreement, 2. Add HEALTHCHECK instructions in Dockerfile.
And when checked with Checkov tool, out of 4 checks 2 were passed and 2 failed.
Failed checks : 1. Ensure that HEALTHCHECK instructions have been added to container images, 2. Ensure that a user for the container has been created.

Then I Created one image in docker using command : docker build -t homelab-web:v1 Docker/  .
docker build reads Dockerfile and creates image of it and then docker runs Dockerfile line by line. 
After Creating image i scanned it with Trivy Container Command: docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image --severity HIGH,CRITICAL homelab-web:v1  .
This command starts the trivy container and allows it to talk with docker and scan the container image inside it based on severity given.
As in Dockerfile i wrote nginx 1.21 which was older version and has 921 vulnerabilities out of which 266 falls under High and Critical categories(Same finding as done on day 4).

Then i fixed the Dockerfile by

FROM nginxinc/nginx-unprivileged:stable-alpine
COPY index.html /usr/share/nginx/html/index.html
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://localhost:8080/ || exit 1
USER nginx

Here, I removed older nginx 1.21 with stable-alpine (it is a smaller images means fewer vulnerabilities).
HEALTHCHECK is added to check whether app is working or not
USER states that container does not run as root.

After adding above things i scanned again where i got 0 Vulnerabilities.
