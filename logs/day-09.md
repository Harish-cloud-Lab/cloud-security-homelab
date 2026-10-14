**Day 9 Hardening Kubernetes manifest and adding RBAC(Role Based Access Control)**
**Goal**: Take Checkov from 21 failed down to a few documented ones, then use RBAC to give an identity read-only access.

Yesterday I deleted my cluster so i recreated it.
kind create cluster --name <cluster-name>

I loaded docker image in that cluster.
kind load docker-image <name>:version --name <cluster-name>

Checked cluster exist or not
kind get clusters
It will show clusters.

Removing old deployment (If present, I deleted it yesterday.)
kind delete deployment,service <file-name>

**Code Hardened**
I replaced the old code to fix those failed checks.
What i fixed.
    -> added **namespaces** in code to keep app out of default.
    -> added **securitycontext** pod to enforce  non-root in kubernetes.
    -> added **securitycontext** in container to stop privilege escalation and to make the file-system read-only and also to drop all linux capabilities. 
    -> added **resources** that limits stop one pod from eating all cpu memory.
    -> added **livenessprobe** By that kubernetes can tell if the app is ready and alive, restart it if not alive.
    -> added **automountServiceAccountToken: false** This stop pods from getting kubernetes API credentials 
    -> added **/tmp** means empty directory with read-only file system. 
    -> added **checkov skip comment** with reason.(A locally loaded image has no registry digest, so accepted that finding.)

Updated Resource from the file 
kubectl apply -f <dir-name>/<file-name>.yaml

Checked Pod Status
kubectl get pods

Checked the user
kubectl exec -n <cluster-name> deploy/<file-name> -- whoami 
It printed nginx.

test webpage
kubectl port-forward -n <cluster-name> service/web 8082:80

**Rescanning with Checkov**
docker run --rm -v ${PWD}/<dir-name>:/<dir-name> bridgecrew/checkov -d /<dir-name> --framework kubernetes --compact --quiet

Result: 88 **Passed**, 03 **Failed**, 01 **Skipped** (Due to Checkov skip comment).

**Failed Checks**
   -> Containers should run as a high UID to avoid host conflict.
   -> Image Pull Policy should be Always.
   -> Minimize the admission of pods which lack an associated NetworkPolicy.


**RBAC** to decide who can access what in cluster.
code <dir-name>/<file-name>.yaml

What added:
   -> ServiceAccount: an identity for a program.
   -> Role: a list of allowed actions, only inside the namespace.
   -> RoleBinding: connects the identity to the role.

**RBAC Contents given to kubernetes**

kubectl apply -f <dir-name>/<file-name>.yml

**Test**

kubectl auth can-i list pods -n <cluster-name> --as=system:serviceaccount:<cluster-name>:pod-reader
kubectl auth can-i delete pods -n <cluster-name> --as=system:serviceaccount:<cluster-name>:pod-reader
kubectl auth can-i list secrets -n <cluster-name> --as=system:serviceaccount:<cluster-name>:pod-reader

The answers were Yes, No, No .
Means Least privilege made visible: it can read pods but cannot delete or touch secrets.

**Note:** At first I got No as the answer of can-i list pods because of a typo (written serviceaccount as servicceaccount)
serviceaccount : exist means it has permissions written.
servicceaccount : does not exist means it has no permission written thats why I got No.

**Note**  A **No** is meaningful when you're sure that identity is spelled right.
Kubernetes doesnt validate the name pass to --as=  so typos fail quietly.


**Solving Failed Checks**
   -> If a container runs as a low UID like 101, that number may match a real user on the host machine. 
      If the container ever escapes, or a volume is shared, it could get the permissions of that host user. 
      UIDs of 10000 or higher are unlikely to match any real host account.    

      *UID value Increased*

    -> "Always" means kubernetes checks registry on every pod start.
        So it always get correct image rather than stale or swapped local copy.
        In my lab, the image is only present in the kind cluster and not in any registry.
        with "Always" kubernetes will try to pull it from internet and fail with "ErrImagePull" thats why i used "IfNotPresent".

        *Skip that in annotations*

    -> By default in kubernetes every pod talks to every other pod.
       A "NetworkPoicy" is the firewall rule for pods.
       Without one, If an attacker compromises one pod, they can reach everything else in the cluster.

       *Assigned Network Policy*

       
       



