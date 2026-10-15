**Scanning Kubernetes in Pipeline and testing NetworkPolicy with Calico**
Goals:
   -> Rebuilding cluster with calico (a network plugin that enforces policies).
   -> Tightening NetworkPolicy and testing it: 
           -> Allowed Traffic = Accepted
           -> Blocked Traffic = Times out
   -> Adding Kubernetes Scanning to Pipeline.

I Created a directory and one file inside that directory for code.
In that code i mentioned **disableDefaultCNI:true** It turns off Kind's built in networking so calico can take over.

Created Cluster and told to read settings from that file.
kind create cluster --name <cluster-name> --config <dir-name>/<file-name>.yaml

Checked node is ready or not.
kubectl get nodes

It Shown 1 Node but status of it is **NotReady**
This is because of disabling built in networking of cluster or kubernetes doesn't considers it healthy.
I disabled kind's built-in networking so calico can enforce.

**Calico Installation**
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.28.0/manifests/calico.yaml

This command installs calico and also create 2 thiings
    -> calico-node - a DaeminSet, so one pod run on every node and sets up pod networking there.
    -> calico-kube-controllers - a Deployment that keeps calico's data sync with with kubernetes.

Start or Rollout calico
kubectl -n kube-system rollout status daemonset/calico-node

After successful rollout check node status it will show **Ready**
kubectl get nodes

Redeploying image in cluster.
kind load docker-image <image-name> --name <cluster-name>
kubectl apply -f <dir-name>/<file-name1>.yaml
kubectl apply -f <dir-name>/<file-name2>.yaml
kubectl get pods -n <cluster-name>

**Tightening Allow rule**
I added **allow-web-ingress** which lets anyone to reach port.
but with that i added namespace: client-ok 
so, only pods from client-ok namespace can reach only to web pod.

**Namespaces creation**
kubectl create namespace client-ok
kubectl create namespace client-bad

**Testing Web Pod before applying policy**

kubectl run test-bad -n client-bad --rm -it --image=busybox:1.36 --restart=Never -- wget -qO- -T 3 http://web.<cluster-name>.svc.cluster.local

This command  shown my web pod's HTML code and with that "pod test-bad deleted from client-bad namespace". (deleted because of rm command)
Means, web pod is not blocking Client-bad.

**Applying Network Policy**
kubectl apply -f <dir-name>/<file-name3>.yaml

**Testing Again**
kubectl run test-bad2 -n client-bad --rm -it --image=busybox:1.36 --restart=Never -- wget -qO- -T 3 http://web.<cluster-name>.svc.cluster.local

Client-bad shows: wget: download timed out means it is **Blocked**

kubectl run test-ok -n client-ok --rm -it --image=busybox:1.36 --restart=Never -- wget -qO- -T 3 http://web.<cluster-name>.svc.cluster.local

Client-ok shows: My HTML page means it is **Allowed**


**Rescanned Locally** if for any errors. (Expecting 0 failed, 2 Skipped and 103 passed)

docker run --rm -v ${PWD}/<dir-name>:/<dir-name> bridgecrew/checkov -d /<dir-name> --framework kubernetes --compact --quiet

Command shown expected output.


**Adding Kubernetes to Pipeline**

code .github/workflows/<file-name>.yml

add kubernetes in checkov step:
**framework: terraform,dockerfile,kubernetes**

Kubernetes added to security pipeline.





