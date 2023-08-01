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
## Arquitectura

En el siguiente diagrama se encuentra la arquitectura general implementada.

![demo_devsu-arq](https://github.com/ignvb/devsu-devops-assessment/assets/140628152/bbe43df1-97e2-4724-9915-b2115e824c18)

Toda la infraestructura construida en AWS para ejecutar este proyecto se encuenta creada utilizando Terraform que se encuentra en */IaC/*. Para el pipeline CI/CD se usó Github Actions y como Container Registry el servicio ECR. A continuación se explica en detalle cada parte.

### Terraform

El script de Terraform realiza las siguientes acciones:
- Crea un nuevo repositorio en ECR para almacenar las imagenes de los contenedores del pipeline CI/CD.
- Crea un usuario IAM con policy restringida a hacer push al repositorio anteriormente creado.
- Obtiene el access_id y access_secret del usuario creado anteriormente, donde este último valor se encuentra encriptado por GPG.
- Se crea un VPC con 3 subnets públicas y 3 subnets privadas haciendo uso de 3 AZ.
- Se crea un cluster en EKS, con un endpoint público (para ser usado en la parte CD), con un managed nodegroup usando una instancia ```t3a.medium``` escalable a 2.
- Se instala en el cluster usando helm dentro del cluster el NLB controller, creando su IAM role correspondiente.
- Se crea en el cluster el namespace de produción ```prod```
- Se instala el servicio Sealed Secrets necesario para versionar secrets encriptados
- Se instala el servicio Metrics Server necesario para el HPA

### Kubernetes

La aplicación crea los siguientes objetos de kubernetes:
- Ingress configurado para rutear el trafico al service
- Service
- Deployment
  - Configurado probes readiness y liveness.
  - Asignado resources de ```100m``` CPU y ```100MB``` de RAM, con limits y requests iguales.
- HPA
  - El horizontal pod autoscale se configuro para mantener 2 replicas escalables a 4 cuando la carga supere el 80%.
- Configmap
  - Para ```DATABASE_NAME```
  - Para ```DJANGO_DEBUG```
- Secret
  - Para ```DJANGO_SECRET_KEY```

Decisiones de diseño:
- Se considero paquetizar la aplicación deplegada en kubernetes en un helm chart por su practicidad y la facilidad de hacer cambios.
- Se condisero el uso de Sealed Secret, una aplicación que permite encriptar los secrets versionados en git. Por lo tanto cada vez que se instala un secret encriptado, este servicio lo intercepta, lo desencripta y crea el objeto secret real.
- Se utilizado ALB como ingress usando el NLB Controller por su practicidad y buena integración con EKS.


### Pipeline CI/CD en Github Action

Se usó Github Action por su buena documentación, soporte, gran cantidad de actions y su cuota gratuida por ser un repositorio público.

#### Pipeline CI

El pipeline se inicia cada vez que se realizan cambios en las siguientes rutas/archivos en el branch main:
- /src/**
- /Dockerfile
- /demo-chart/**

El siguiente diagrama muestra las etapas del pipeline CI.

![demo_devsu-ci](https://github.com/ignvb/devsu-devops-assessment/assets/140628152/666cdb2f-a919-4495-bf7b-d4e034435e9a)

Decisiones de diseño:
- Para ejecutar los Unit Test, se hizo uso de las siguientes herramientas de python: ```pytest-django```, ```coverage```, ```tox```.
- Para el static code analysis, vulnerability y análisis del covarage report se utilizo la herramienta sonarqube y sonarcloud, la cuál ofrecia todo gratuitamente por ser un proyecto público. Se encontró un error cuando sonarqube analizaba el código del coverage.xml producto de discrepancias entre las rutas dentro del workflow del action y el volumen que lo montaba dentro del docker, para resolver estó se agrego un step previó el cuál modifica el ```coverage.xml``` reemplanzo la ruta por una compatible con el docker de sonarqube.
- Para almacenar la imagen del contenedor se creo un usuario IAM con permisos restringidos sólo para trabajar con el repositorio creado para este proyecto (se hace desde Terraform)

### Pipeline CD

El siguiente diagrama muestra las etapas del pipeline CD.

![demo_devsu-cd](https://github.com/ignvb/devsu-devops-assessment/assets/140628152/f2da15ff-0509-4e9d-baad-f2b7695e49e8)

Decisiones de diseño:
- Se usó otro usuario IAM con permisos para conectarse al cluster e instalar el paquete Helm. Por motivos de tiempo esto se configuro usando Terraform y fue creada manualmente.
- Para reinstalar el demo-chart, se uso action ```bitovi/github-actions-deploy-eks-helm@v1.2.4``` que se encuentra bien documentado y mantenido.
