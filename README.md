# Generador de informe OSINT 

Servicio API basada en FastAPI que realiza análisis OSINT automatizado sobre dominios, identificando subdominios expuestos, configuraciones de seguridad, tecnologías utilizadas y posibles vulnerabilidades (CVE) a partir de información pública. Los resultados se procesan y generan en informes estructurados que se almacenan en S3, mientras que cada ejecución es registrada en una base de datos para su seguimiento, permitiendo consultar el estado, historial y resultados de los análisis mediante endpoints REST.


## 🚸 Setup First Time

(create venv)
```
python3 -m venv venv-colcert-scanner
source venv-colcert-scanner/bin/activate
pip install -r requirements.txt
```

## 📚️ Libraries

Add libs
```
pip3 install requests dnspython docxtpl
pip freeze > requirements.txt
```


## 👨‍💻 Run Server on local
```
python3 main.py
```
Tambien se puede usar el debbuger de VScode

## 🎯 Endpoints

### Scan a domain
```
curl --location '127.0.0.1:8000/scan' \
--header 'Content-Type: application/json' \
--data '{
    "domain": "https://procesamientoe3idc2026.registraduria.gov.co/"
}'
```

### Get last scans
```
curl --location '127.0.0.1:8000/scan'
```

### Get One scan
```
curl --location '127.0.0.1:8000/scan/9'
```

## 🚀 Docker

```
docker build -t colcert-scanner .
docker rm -f colcert-scanner
docker run --name colcert-scanner -d -p 8000:8000 --env-file .env colcert-scanner
```