# webhook-prevent-delete-denyall

Kubernetes webhook that prevents user from deleting NP named denyall

# Build

Build go code (tested with go version go version 1.24.2):

```bash
cd webhook
go mod init webhook-prevent-delete-denyall
go mod tidy
```

Create the container image:

```bash
IMG_REGISTRY_USER=<user>
podman login quay.io
podman build -t quay.io/$IMG_REGISTRY_USER/webhook-prevent-delete-denyall .
podman push quay.io/$IMG_REGISTRY_USER/webhook-prevent-delete-denyall

cd ..
CONTAINER_IMAGE_REGISTRY=quay.io/$IMG_REGISTRY_USER
sed -i "s#<container-registry>#${CONTAINER_IMAGE_REGISTRY}#g" manifests/deployment.yaml
```

# Create certs

```bash
mkdir certs
cd certs
# Generate the CA private key
openssl genrsa -out ca.key 2048

# Generate the CA certificate (valid for 1 year in this example)
# You'll be prompted for details (Country, Org, etc.). You can leave most blank,
# but set a Common Name (CN) for identification (e.g., "My Webhook CA").
openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 -out ca.crt \
  -subj "/CN=My Webhook CA"

# Generate the server private key
openssl genrsa -out tls.key 2048  

# Create a CSR configuration file (e.g., csr.conf)
cat <<EOF > csr.conf
[ req ]
default_bits = 2048
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[ dn ]
# IMPORTANT: Set CN to <service-name>.<namespace>.svc
CN = denyall-netpol-webhook-svc.denyall-webhook.svc

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
# Also include the DNS name here
DNS.1 = denyall-netpol-webhook-svc.denyall-webhook.svc
EOF

# Generate the CSR using the server key and the config file
openssl req -new -key tls.key -out tls.csr -config csr.conf

# Sign the server's CSR with the CA key and certificate (valid for 1 year)
openssl x509 -req -in tls.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out tls.crt -days 365 -sha256 -extfile csr.conf -extensions req_ext
```

Update webhook with CA:

```
cd ..
# Base64 encode the CA certificate
CA_BUNDLE_BASE64=$(cat certs/ca.crt | base64 | tr -d '\n')
sed -i "s/<BASE64_ENCODED_CA_CERTIFICATE>/${CA_BUNDLE_BASE64}/g" manifests/webhook.yaml
```

# Deploy webhook

```bash
oc create namespace denyall-webhook
oc -n denyall-webhook create secret tls denyall-netpol-webhook-tls \
  --cert=certs/tls.crt \
  --key=certs/tls.key
cd manifests
oc apply -f .
```

# Testing

```bash
oc create namespace np-test

cat <<EOF | oc apply -f -
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: denyall
  namespace: np-test
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
EOF

oc delete networkpolicy denyall -n np-test
```

You should get the following error message:

```bash
$ oc delete networkpolicy denyall -n np-test
Error from server: admission webhook "validate-denyall-netpol.example.com" denied the request: Deleting the NetworkPolicy named 'denyall' is not allowed by policy.
```

# Add denyall NP to OpenShift Project Template

Additionally, you can add a denyall NP to OpenShif Template. That way you will garantee that every new project will have a denyall NP.

```bash
oc create -f template/template.yaml
```

Edit the project configuration:

```bash
oc edit project.config.openshift.io cluster
```

Modify the `projectRequestTemplate` field, for example:

```bash
spec:
  projectRequestTemplate:
    name: project-with-denyall-networkpolicy
```
