**Kubernetes Basics**

Goal- Create a local cluster, deploy your image to it, see it running, then scan the Kubernetes file with Checkov to see what’s insecure

Installed Kubernetes Kind and Kubectl through powershell and verified them.
**Kubernetes** A system that runs and manages containers across machines.
**Kind** (Kubernetes in Docker) runs a small cluster inside docker container in laptop.
**Kubectl** command line tool used to talk to a cluster.

Created Cluster.
kind create cluster --name <name>  <-- Creates cluster.
kubectl get nodes   <-- checks status

Loaded Image in cluster (Cluster cannot see images from system automatically.)
kind load docker-image homelab-web:v2 --name <name>

Directory Creation.
mkdir <name>
code <name>/<file-name>.yml 

Deployment 
kubectl apply -f <dir-name>/<file-name>.yml
kubectl get pods
kubectl get delpoyments
kubectl get services

Opening service in browser.
kubectl port-forward service/<file-name> <port-number>:80

I have seen message **Hello, from my Cloud Security Homelab**

Confirm who it runs as.
kubectl exec deploy/<file-name> -- whoami

I have seen **nginx** there. Its the same non-root user i saw on day 5.

Scanning and Manifesting with checkov.
docker run --rm -v ${PWD}/<dir-name>:/<dir-name> bridgecrew/checkov -d /<dir-name> --framework kubernetes --compact --quiet

Kubernetes Scan Results -> **69 Passed** and **21 Failed** , Skipped Checks 0
**Failed Checks**
   -> Image should use digest.
   -> Memory Limits should be set.
   -> Ensure that service account tokens are only mounted where necessary.
   -> CPU limits should be set.
   -> Memory request should be set. 
   -> Apply security context to your pod and container.
   -> Liveness probe should be configured.
   -> CPU request should be set.
   -> The default namespaces should not be used. *2
   -> Ensure that the seccomp profile is set to docker/default or runtime/default.
   -> Minimize the admission of root containers.
   -> Readiness probe should be configured.
   -> Minimize the admission of containers with capabilities assigned.
   -> Containers should run as high UID to avoid host conflict.
   -> Minimize the admission of containers with NET_RAW capability.
   -> Use read-only file system for container where possible.
   -> Containers should not run with "allowPriviledgeEscalation".
   -> Image Pull Policy should be Always.
   -> Apply Security Context to your containers.
   -> Minimize the admission of pods which lacks an associated NetworkPolicy .

Even though the image is hardened, failures are there.
I Pushed this to Github.
Though right now CI/CD Pipeline only scans Dockerfile,terraform  the action wont turn red.

Deleted Cluster through Powershell.
kind delete cluster --name <name> 


