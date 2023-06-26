variable "profile" {
    description = "AWS Profile"
    type        = string
    default     = "justctf"
}

variable "region" {
    description = "AWS region for all resources."
    type        = string
    default     = "eu-west-1"
}

variable "challenge_difficulty" {
    description = "Number of zeros for difficulty"
    type        = string
    default     = "26"
}

variable "prefix_length" {
    description = "Lenght of the prefix"
    type        = string
    default     = "22"
}

variable "validity_time" {
    description = "How long (in seconds) should the challenge be valid"
    type        = string
    default     = "3600"
}

variable "role_name" {
    description = "Name of the role which gives other set of available actions"
    type        = string
    default     = "fishy_moderator"
}

variable "flag" {
    description = "Flag"
    type        = string
    default     = "justCTF{D0nt_trY_Us1ng_C0gn1to_1f_y0u_l1ke_g0od_sle3p}"
}

variable "key" {
    description = "Key (hex encoded) for AES encryption"
    type        = string
    default     = "7b655eeb9f7607730d47e53d12cf8f8c"
}

variable "nonce" {
    description = "Nonce (hex encoded) for AES encryption"
    type        = string
    default     = "e8b89d0c42306d45a335421ba9ad6b62"
}

variable "waf_limit" {
    description = "How many request are allowed during 5-minute window?"
    type        = number
    default     = 1000
}