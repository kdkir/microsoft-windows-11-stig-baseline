#!/bin/sh
# Entry point for the Terraform container the Logic App starts.
# ACTION is "apply" or "destroy". Everything else arrives as environment
# variables (TF_VAR_*, ARM_*, TF_STATE_*), set by the Logic App.
set -eu

: "${ACTION:?}" "${TF_VAR_run_id:?}" "${TF_STATE_ACCOUNT:?}" "${TF_STATE_CONTAINER:?}"
TF_VAR_status_url=${TF_VAR_status_url:-}

cd "$(dirname "$0")"

terraform init -input=false -no-color \
  -backend-config="storage_account_name=$TF_STATE_ACCOUNT" \
  -backend-config="container_name=$TF_STATE_CONTAINER" \
  -backend-config="key=run-$TF_VAR_run_id.tfstate" \
  -backend-config="use_azuread_auth=true" \
  -backend-config="use_msi=true"

case "$ACTION" in
  apply)
    if ! terraform apply -input=false -no-color -auto-approve; then
      # Let the pipeline know now instead of waiting for its timeout.
      apk add --no-cache curl >/dev/null 2>&1 || true
      printf '{"exit_code": -1, "error": "Terraform apply failed; see the Logic App run and container logs."}' |
        curl -fsS -X PUT -H 'x-ms-blob-type: BlockBlob' -H 'Content-Type: application/json' \
          --data-binary @- "$TF_VAR_status_url" || true
      exit 1
    fi
    ;;
  destroy)
    # Wait for an apply that is still running (e.g. after a pipeline timeout).
    terraform destroy -input=false -no-color -auto-approve -lock-timeout=90m
    ;;
  *)
    echo "Unknown ACTION '$ACTION'" >&2
    exit 2
    ;;
esac
