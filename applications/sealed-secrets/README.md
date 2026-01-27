# Sealed Secrets (kubeseal) Usage
### Prerequisites
- Sealed Secrets Controller is already deployed in the Kubernetes cluster
- A valid `~/.kube/config`
- Docker is available

## 1. Fetch the Public Certificate
Fetch the public certificate from the Sealed Secrets Controller.

```bash
docker run --rm -i \
  --name kubeseal \
  --mount type=bind,source="$HOME/.kube/config",dst="$HOME/.kube/config",ro \
  bitnami/sealed-secrets-kubeseal:0.34.0 \
  --fetch-cert \
  --controller-namespace=sealed-secrets \
  --controller-name=sealed-secrets \
  --kubeconfig $HOME/.kube/config \
  > public.crt
```

### Notes
- Adjust the namespace and controller name to match your environment
- `public.crt` is used **only for encryption** and can be safely shared
- The private key is stored only inside the controller

## 2. Encrypt a Secret
Convert a standard Kubernetes `Secret` manifest into a `SealedSecret` using the public certificate.

```bash
docker run --rm -i \
  --name kubeseal \
  --mount type=bind,source="$PWD/public.crt",dst="/cert/public.crt",ro \
  bitnami/sealed-secrets-kubeseal:0.34.0 \
  --cert=/cert/public.crt \
  --format=yaml \
  < tmp-secret.yaml \
  > sealed-secret.yaml
```

### Input / Output
- **Input**: `tmp-secret.yaml` (plain Kubernetes Secret)
- **Output**: `sealed-secret.yaml` (safe to commit to Git)

## 3. Apply the SealedSecret

Deploy the SealedSecret to the cluster.

```bash
kubectl apply -f sealed-secret.yaml
```
