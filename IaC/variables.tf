variable "ecr_repo" {
    description = "Nombre del repositorio a crear en ECR"
    type        = string
    default     = "demo"
}

variable "image_mutability" {
    description = "Mutabilidad de las imagenes de los contenedores"
    type        = string
    default     = "IMMUTABLE"
}

variable "encrypt_type" {
    description = "Tipo de encriptación para ECR"
    type        = string
    default     = "KMS"
}

variable "tags" {
    description = "Mapa con tags"
    type        = map(string)
    default     = {}
}

variable "ci_name" {
    description = "Servicio de CI que usara ECR"
    type        = string
    default     = "CI"
}
