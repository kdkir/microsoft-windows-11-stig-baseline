variable "run_id" {
  description = "Pipeline run ID; used in resource names and the state key."
  type        = string
}

variable "location" {
  type = string
}

variable "resource_group_name" {
  description = "Resource group the platform created for workstations."
  type        = string
}

variable "subnet_id" {
  description = "Subnet (with NAT gateway for outbound internet) for the workstation."
  type        = string
}

variable "vm_size" {
  type    = string
  default = "Standard_D2s_v5"
}

variable "image_sku" {
  description = "Windows 11 Marketplace SKU, e.g. win11-24h2-pro or win11-24h2-ent."
  type        = string
  default     = "win11-24h2-ent"
}

variable "license_type" {
  description = "Set to Windows_Client if you have eligible multi-tenant hosting rights."
  type        = string
  default     = null
}

# SAS links from the pipeline. Only needed for apply; empty on destroy.
variable "script_url" {
  type      = string
  default   = ""
  sensitive = true
}

variable "profile_url" {
  type      = string
  default   = ""
  sensitive = true
}

variable "results_url" {
  type      = string
  default   = ""
  sensitive = true
}

variable "status_url" {
  type      = string
  default   = ""
  sensitive = true
}
