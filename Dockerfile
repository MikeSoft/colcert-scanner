# Imagen base ligera
FROM python:3.11-slim

# Evita archivos .pyc y buffer
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Instalar dependencias del sistema + Go
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    git \
    wget \
    ca-certificates \
    golang-go \
    && apt-get clean

# Configurar PATH para Go
ENV PATH="/root/go/bin:${PATH}"

# Instalar subfinder
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN subfinder -h

# Instal amass
RUN go install -v github.com/owasp-amass/amass/v4/...@master
RUN amass -h

# Install assetfinder
RUN go install github.com/tomnomnom/assetfinder@latest
RUN assetfinder -h

# Crear directorio de trabajo
WORKDIR /app

# Copiar requirements primero (mejor cache)
COPY requirements.txt .

# Instalar dependencias Python
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el código
COPY . .

# Exponer puerto
EXPOSE 8000

# Comando de ejecución
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]