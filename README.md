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

Cuenta AWS con permisos de administrador configurada en el hosts e instalar las dependencias detalladas.

## Como ejecutar este proyecto

### Configuración incial
1. Crear certificados para sealed secret y encriptar los secrets del helm chart
```bash
openssl req -x509 -days 365 -nodes -newkey rsa:4096 -keyout "./IaC/certs/private.crt" -out "./IaC/certs/public.key" -subj "/CN=sealed-secret/O=sealed-secret"
```
Luego, encriptar encriptar los secrets del helm chart
```bash
echo -n <value-to-encrypt> | kubeseal --raw --scope strict --name <name-secret> --namespace <namespace> --cert ./IaC/certs/public.key --from-file=/dev/stdin
```
Finalmente actualizar el valor en ```/demo-chart/values.yaml``` en la sección secrets.
2. Crear llave GPG y codificar la llave pública base 64 
```bash
pg --full-generate-key
gpg --output public.pgp --export <email@example.com>
base64 public.pgp
```
Copiar el resultado en la variable **public_pgp_key** en ```/IaC/terraform.tfvars```
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

Toda la infraestructura construida en AWS para ejecutar este proyecto se encuenta creada utilizando Terraform que se encuentra en ```*/IaC/*```. Para el pipeline CI/CD se usó Github Actions y como Container Registry el servicio ECR. A continuación se explica en detalle cada parte.

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

#### Providers:

| Nombre | Version |
|------|---------|
| terraform | >= 1.5 |
| aws | >= 5.9.0 |
| terraform-aws-modules/vpc/aw | >= 5.1.0 |
| terraform-aws-modules/eks/aws | >= 19.15.4 |
| kubernetes | >= 2.10.0 |
| helm | >= 2.10.1 |

#### Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| ecr_repo | Nombre del repositorio a crear en ECR | `string` | `demo` | yes |
| image_mutability | Mutabilidad de las imagenes de los contenedores en ECR | `string` | `IMMUTABLE` | no |
| encrypt_type | Tipo de encriptación para ECR | `string` | `KMS` | no |
| ci_name | Servicio de CI que usara ECR | `string` | `CI` | yes |
| public_pgp_key | Key publica de GPG en base64 | `string` | "" | yes |
| vpc_name | Nombre VPC a crear en AWS | `string` | `vpc-demo` | yes |
| cluster_name | Nombre Cluster a crear en AWS | `string` | `cluster-demo` | yes |

#### Outputs

| Name | Description |
|------|-------------|
| access_id | Access id del usuario para ECR |
| access_secret | Access key del usuario en base64 para el ECR |
| cluster_endpoint | Endpoint al control plane del EKS |
| cluster_name | Nombre del cluster en EKS |

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

#### Decisiones de diseño
- Se considero paquetizar la aplicación deplegada en kubernetes en un helm chart por su practicidad y la facilidad de hacer cambios.
- Se condisero el uso de Sealed Secret, una aplicación que permite encriptar los secrets versionados en git. Por lo tanto cada vez que se instala un secret encriptado, este servicio lo intercepta, lo desencripta y crea el objeto secret real.
- Se utilizado ALB como ingress usando el NLB Controller por su practicidad y buena integración con EKS.


### Pipeline CI/CD en Github Action

Se usó Github Action por su buena documentación, soporte, gran cantidad de actions y su cuota gratuida por ser un repositorio público.

#### Pipeline CI

El pipeline se inicia cada vez que se realizan cambios en las siguientes rutas/archivos en el branch main:
- ```/src/**```
- ```/Dockerfile```
- ```/demo-chart/**```

El siguiente diagrama muestra las etapas del pipeline CI.

![demo_devsu-ci](https://github.com/ignvb/devsu-devops-assessment/assets/140628152/666cdb2f-a919-4495-bf7b-d4e034435e9a)

#### Decisiones de diseño
- Para ejecutar los Unit Test, se hizo uso de las siguientes herramientas de python: ```pytest-django```, ```coverage```, ```tox```.
- Para el static code analysis, vulnerability y análisis del covarage report se utilizo la herramienta sonarqube y sonarcloud, la cuál ofrecia todo gratuitamente por ser un proyecto público. Se encontró un error cuando sonarqube analizaba el código del coverage.xml producto de discrepancias entre las rutas dentro del workflow del action y el volumen que lo montaba dentro del docker, para resolver estó se agrego un step previó el cuál modifica el ```coverage.xml``` reemplanzo la ruta por una compatible con el docker de sonarqube.
- Para almacenar la imagen del contenedor se creo un usuario IAM con permisos restringidos sólo para trabajar con el repositorio creado para este proyecto (se hace desde Terraform)

### Pipeline CD

El siguiente diagrama muestra las etapas del pipeline CD.

![demo_devsu-cd](https://github.com/ignvb/devsu-devops-assessment/assets/140628152/f2da15ff-0509-4e9d-baad-f2b7695e49e8)

#### Decisiones de diseño
- Se usó otro usuario IAM con permisos para conectarse al cluster e instalar el paquete Helm. Por motivos de tiempo esto se configuro usando Terraform y fue creada manualmente.
- Para reinstalar el demo-chart, se uso action ```bitovi/github-actions-deploy-eks-helm@v1.2.4``` que se encuentra bien documentado y mantenido.

## Limitaciones

### Sealed Secret

Por defecto, el servicio crea llaves de encriptación la primera vez que se inicia. Para evitar la necesidad de reencriptar los secrets cada vez que se haga un bootstrap de la infraestructura, se decidio crear dichas llaves de manera local y cargarlas desde el script de Terraform. Se entiende de que esta no es la mejor desición pero se considero por razones practicas.

Lo anteior plantea dos problemas:

1. La llave privada estará de manera local y que por razones de seguridad no se versionaron es este repositorio y queda expusta, lo cuál es una pésima practica en producción.
2. Para ser usado por terceras personas, estás deben crear sus propias par de llaves y usar la publica para encriptar el secret nuevamente.

Una posible solución a está limitante es usar un servicio externo para almacenar las llaves de manera segura como AWS KMS y que estás sean recuperadas por Terraform cuando las necesite.

### HTPPS en ALB

Al no tener un dominio disponible, no fue posible asignar un certificado al ingress de ALB. Con un dominio disponible, se puede crear certificados en ACM, validandolos y obteniendo un ARN que luego puede ser registrado en ALB.

## Mejoras y optimizaciones

Las siguientes son mejoras consideradas pero que no se alcanzaron a implementar por tiempo.

- Creación de un IAM user realizando un role binding con las cuentas de kubernetes para usar los ACL y restringir los permisos del pipeline CD.
- Utilizar gunicorn para ejecutar la aplicación.
- Crear un nuevo endpoint en django dedicado a los healthchek.
- Crear un dominio que apunte al dns del NLB de AWS para ingresar con una dirección más amigable y segura.
