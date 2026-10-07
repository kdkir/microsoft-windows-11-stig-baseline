variable "subscription_id" {
  type = string
}

variable "location" {
  type    = string
  default = "eastus2"
}

variable "name_prefix" {
  description = "Short prefix for resource names."
  type        = string
  default     = "inspecw11"
}

variable "github_repository" {
  description = "owner/repo allowed to log in to Azure from GitHub Actions."
  type        = string
  default     = "kdkir/microsoft-windows-11-stig-baseline"
}

variable "github_environment" {
  description = "GitHub Actions environment the scan job runs in (must match the workflow)."
  type        = string
  default     = "windows11-scan"
}

variable "terraform_image" {
  description = "Container image the Logic App uses to run Terraform."
  type        = string
  default     = "hashicorp/terraform:1.13.3"
}

variable "run_retention_days" {
  description = "Days to keep per-run blobs (profile archive, results, state)."
  type        = number
  default     = 30
}
