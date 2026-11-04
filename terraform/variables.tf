variable "region" {
  type    = string
  default = "us-east-1"
}

variable "use_emulator" {
  description = "Send every call to a fake AWS (moto server) on localhost:4566 instead of real AWS."
  type        = bool
  default     = false
}

variable "name_suffix" {
  description = "Added to bucket names. S3 names are global, so on real AWS use something unique like your account ID, for example -123456789012."
  type        = string
  default     = ""
}

variable "plant_old_lambda" {
  description = "Plant a function on a retired runtime. AWS refuses to create these on real accounts, so set false there."
  type        = bool
  default     = true
}

variable "create_instance" {
  description = "Create one small EC2 instance (about one cent per hour). Off by default and not used on the fake AWS."
  type        = bool
  default     = false
}

variable "alert_email" {
  description = "If set, create a monthly cost budget that emails this address at 80 percent of the limit."
  type        = string
  default     = ""
}

variable "budget_limit_usd" {
  type    = number
  default = 20
}
