variable "resource_group_location" {
  default     = "uksouth"
  description = "Location of the resource group."
}

variable "prefix" {
  type        = string
  default     = "testing"
  description = "Prefix of the resource name"
}

variable "ext_ip" {
  type        = string
  default     = "154.61.57.200"
  description = "External IP to allow traffic from"
}

variable "vmSize" {
  type        = string
  default     = "Standard_DS1_v2"
  description = "VM SKU size in Azure"
}