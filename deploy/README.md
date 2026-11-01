# Deployment

The container is built from an immutable official Go image and ships a statically
linked gateway and CA trust store in a scratch runtime. It runs as UID/GID 65532
with no shell or package manager. It can launch the bundled demo subprocess;
other stdio executables need a separately reviewed image or sidecar arrangement.

## Local container

```sh
docker build -t tool-gateway:local .
docker volume create tool-gateway-audit
python3 - <<'PY'
import json
from pathlib import Path
p=json.loads(Path('examples/policy.json').read_text())
p['listen']='0.0.0.0:8844'
Path('policy.container.local.json').write_text(json.dumps(p))
PY
export TOOL_GATEWAY_TOKEN="$(openssl rand -hex 32)"
docker run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  --tmpfs /tmp:rw,nosuid,noexec,size=32m \
  -e TOOL_GATEWAY_TOKEN -p 127.0.0.1:8844:8844 \
  -v "$PWD/policy.container.local.json:/etc/tool-gateway/policy.json:ro" \
  -v tool-gateway-audit:/data tool-gateway:local
```

Do not expose this plain HTTP port publicly. Configure TLS and workload access
controls at ingress. Runtime policy and credentials are deliberately not baked
into the image.

For an enterprise TLS-inspecting build network, supply an approved public CA
bundle with `docker build --secret id=build_ca,src=/secure/build-ca.pem ...`.
The optional secret affects dependency download only and is not copied into the
runtime image. Never disable TLS verification. For private upstream CAs, mount a
separately approved runtime trust bundle and configure `SSL_CERT_FILE` explicitly.

## Kubernetes example

`kubernetes.yaml` is a **single-replica demonstration**, not a claim that your
cluster has been provisioned. Build/load the image for a local cluster, or replace
the image reference and pull policy with your own immutable registry digest.

```sh
kubectl create configmap tool-gateway-policy \
  --from-file=policy.json=policy.container.local.json
# Supply the token through your secret-management workflow; do not commit it.
kubectl create secret generic tool-gateway-token \
  --from-literal=token="$TOOL_GATEWAY_TOKEN"
kubectl apply -f deploy/kubernetes.yaml
```

The example uses a private volume, read-only root filesystem, non-root user,
dropped capabilities, bounded writable temporary storage, no service-account
token, readiness/liveness probes, resource limits and default-deny egress. Only
pods explicitly labeled `tool-gateway-client=true` may reach the service.
Customize namespace/ingress/network rules before deploying real upstreams.

Do not increase replicas on this shared-journal Deployment. For scaling, provision
one journal volume per replica (for example, independent StatefulSet claims),
separate task ownership and sticky routing at the ingress. Distinct users/tenants
also need distinct workload tokens and policies. Sessions do not migrate or
resume after a replica restart. See `docs/architecture.md` and `docs/operations.md`.

No cloud resources or image registries are created by the build or examples.
