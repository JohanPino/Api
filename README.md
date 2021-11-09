# API

## Comandos para iniciar:
npm install
npm start

# RECOMENDACIONES: 
RECOMENDACION 1: DEBE TENER INSTALADO NODEJS 
#### ENLACE: https://nodejs.org/en/download/

RECOMENDACION 2: TANTO EL API COMO EL CLIENTE DEBEN INICIARSE A LA VEZ 


# COMO SE REALIZO EL PROYECTO

Se desarrolló un API con NodeJS y la librería Express, como motor de base de datos se usó PostgreSQL usando DBaaS (Base de datos como servicio) que provee Heroku. (Las credenciales de la BD se encuentran en el archivo config del servidor)

En la BD encontramos dos tablas: 
USERS: será la encargada de almacenar la información para realizar la autenticación del usuario.
PASSWORDS_LOG: Esta tabla se alimentará por medio de un Trigger que se disparara cada que ocurra un evento INSERT o UPDATE en la tabla USERS, y servirá a la hora de la validación para que las contraseñas no se reutilicen. (El esquema de la BD y la definición de Stored Procedures y Trigger se encuentran en la carpeta database del servidor)

La comunicación entre API(Servidor) y Base de datos se hace por medio de Stored Procedures.

El lado cliente se desarrolló con la librería ReactJS.
La validación de los datos del lado del cliente se realizó usando expresiones regulares.
La encriptación de las contraseñas se realizó usando el algoritmo SHA-256.
