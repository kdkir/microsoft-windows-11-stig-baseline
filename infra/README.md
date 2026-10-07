# Windows 11 STIG scan pipeline

On every commit, `.github/workflows/windows11-scan.yml` scans a brand-new
Windows 11 workstation in Azure with this profile and reports the results.

```
GitHub Actions ──► Azure Function ──► Logic App ──► container running Terraform
  check + archive     (StartScan)        │               │
  upload to Blob                         │               ▼
  wait for status.json ◄─────────────────┼──── Windows 11 VM: install CINC Auditor,
  report + teardown                      │     run profile, upload results.json
                                         └──── deletes the container when done
```

1. **Pipeline:** runs `cinc-auditor check` and `cinc-auditor archive`, then uploads
   the archive, `scripts/run-scan.ps1` and the `workstation/` Terraform to the
   `runs` container under `<run id>/`. It creates short-lived SAS links and calls
   the Function with `action=apply`.
2. **Function** (`function/`): validates the request and forwards it to the Logic App.
3. **Logic App** (`platform/logic_app.tf`): starts an Azure Container Instance
   from the `hashicorp/terraform` image. The container downloads `workstation/` and
   runs `run.sh`, which runs `terraform apply` with state in the `tfstate` container.
4. **Workstation** (`workstation/`): a Windows 11 VM with no public IP. Its Custom
   Script Extension runs `run-scan.ps1` as SYSTEM, which installs CINC Auditor,
   runs the profile with `--reporter json --enhanced-outcomes` and uploads
   `results.json` and `status.json`.
5. **Pipeline:** waits for `status.json`, prints the JSON, saves it as the
   `cinc-results-*` artifact and writes a summary. It then calls the Function with
   `action=destroy`, which runs `terraform destroy`.

**Pass rule:** the check passes when CINC Auditor ran the profile and produced
JSON (exit code 0, 100 or 101). Failed STIG controls show in the summary and as
a warning, but do not fail the build. The rule lives in `scripts/report-results.sh`.

## One-time setup

Prerequisites: Azure CLI, Terraform 1.6+, and Owner (or Contributor + User
Access Administrator) on the subscription.

1. Register the resource providers once per subscription:

   ```sh
   for ns in Microsoft.ContainerInstance Microsoft.Logic Microsoft.Web \
             Microsoft.Compute Microsoft.Network Microsoft.Storage Microsoft.ManagedIdentity; do
     az provider register --namespace "$ns"
   done
   ```

2. Create the shared resources:

   ```sh
   cd infra/platform
   terraform init
   terraform apply -var subscription_id=<subscription id>
   ```

   Keep this Terraform state somewhere safe; it is the only record of these resources.

3. In GitHub, go to **Settings → Environments** and create an environment named
   `windows11-scan`. Add the following to it:
   - Variables from `terraform output github_variables`: `AZURE_CLIENT_ID`,
     `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`, `AZURE_STORAGE_ACCOUNT`.
   - Secret `AZURE_FUNCTION_URL` from `terraform output -raw azure_function_url`.

The workflow logs in to Azure with GitHub OIDC (a federated credential on a
managed identity), so no Azure passwords are stored in GitHub.

## Things to know

- **Licensing:** the VM uses the `windows-11` Marketplace image (`win11-24h2-ent`
  by default). Running Windows 11 in Azure requires eligible licensing. Set
  `license_type = "Windows_Client"` in `workstation/variables.tf` if you have
  multi-tenant hosting rights.
- **Cost:** a `Standard_D2s_v5` VM runs for each commit for as long as the scan
  takes, plus the NAT gateway runs all the time. Per-run blobs expire after 30 days.
- **Failures:** if Terraform fails, the container posts a failure to `status.json`
  so the pipeline fails quickly. The failed container is kept so you can read its
  logs in the portal (Container instances → `tf-apply-<run id>` → Logs). Delete it
  afterwards.
- **Teardown:** destroy runs even when the scan fails. If a run is cancelled before
  teardown, delete the leftover `vm-inspec-<run id>` resources from the resource
  group. Every resource is tagged with `run_id`.
- **Docker Hub:** the container image is pulled anonymously from Docker Hub. If
  you hit pull rate limits, mirror the image into an Azure Container Registry and
  change `terraform_image`.
- **Inputs:** the profile runs with the defaults in `inspec.yml`. To tailor them,
  add an inputs file to the archive or extend `run-scan.ps1` to pass `--input-file`.
