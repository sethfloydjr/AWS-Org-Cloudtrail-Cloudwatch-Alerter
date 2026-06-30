variable "name" {
  description = "Name (path) of the secret, e.g. secops/cloudwatch-alerts/jira-credentials."
  type        = string
}

variable "description" {
  description = "Human-readable description of what the secret holds."
  type        = string
  default     = ""
}

variable "owner" {
  description = "Owning team, applied as a tag."
  type        = string
  default     = "SECOPS"
}

variable "service" {
  description = "Service this secret belongs to, applied as a tag."
  type        = string
  default     = ""
}

variable "recovery_window_in_days" {
  description = "Days AWS retains the secret after deletion before permanent removal. Set to 0 for immediate deletion (handy in non-prod)."
  type        = number
  default     = 30
}
