# devsu-devops-assessment

[![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=ignvb_devsu-devops-assessment&metric=code_smells)](https://sonarcloud.io/summary/new_code?id=ignvb_devsu-devops-assessment)
[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=ignvb_devsu-devops-assessment&metric=bugs)](https://sonarcloud.io/summary/new_code?id=ignvb_devsu-devops-assessment)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=ignvb_devsu-devops-assessment&metric=coverage)](https://sonarcloud.io/summary/new_code?id=ignvb_devsu-devops-assessment)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=ignvb_devsu-devops-assessment&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=ignvb_devsu-devops-assessment)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=ignvb_devsu-devops-assessment&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=ignvb_devsu-devops-assessment)
[![devsu-assesment-ci](https://github.com/ignvb/devsu-devops-assessment/actions/workflows/main.yaml/badge.svg)](https://github.com/ignvb/devsu-devops-assessment/actions/workflows/main.yaml)

Este repositorio contiene el desarrollo de la prueba técnica de DevOps para Devsu.

## Dependencias utilizadas

- Terraform v1.5.3
- Openssl v3.1.1
- GnuPG v2.2.41
- AWS CLI v2.7.6
- Kubeseal v0.20.5
- Helm v3.12.0

# Requisitos

Cuenta AWS con permisos de administrador configurada en el hosts e instalar las dependencias.

## Como ejecutar este proyecto

### Configuración incial
1. Crear certificados para sealed secret y encriptar los secrets del helm chart
```bash
openssl req -x509 -days 365 -nodes -newkey rsa:4096 -keyout "./IaC/certs/private.crt" -out "./IaC/certs/public.key" -subj "/CN=sealed-secret/O=sealed-secret"
```
Luego, para encriptar de nuevo el valor de los secrets
```bash
echo -n <value-to-encrypt> | kubeseal --raw --scope strict --name <name-secret> --namespace <namespace> --cert ./IaC/certs/public.key --from-file=/dev/stdin
```
Finalmente actualizar el valor en */demo-chart/values.yaml* en la sección secrets.
2. Crear llave GPG y codificar la llave pública base 64 
```bash
pg --full-generate-key
gpg --output public.pgp --export <email@example.com>
base64 public.pgp
```
Copiar el resultado en la variable **public_pgp_key** en */IaC/terraform.tfvars*
### Creación de la infrastructura en AWS
1. Ejecutar script en terraform
```bash
cd IaC/
terraform init
terraform apply
```
2. Actualizar secrets en Github Action
Para obtener el AWS_ACCESS_ID
```bash
terraform output -raw access_id
```
Para obtener el AWS_ACCESS_SECRET
```bash
terraform output -raw access_secret | base64 --decode | gpg --decrypt
```
3. Instalar el chart que contiene la aplicación demo usando helm:
```bash
helm install devsu demo-chart --namespace prod
```
