# Use a imagem oficial do Python
FROM python:3.11-slim

# Instala dependências de build e SQLite
RUN apt-get update && \
    apt-get install -y gcc libpq-dev sqlite3 python3-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

COPY . .

# Expor porta padrão do Railway
EXPOSE 8080

CMD ["gunicorn", "--bind", "0.0.0.0:8080", "app:app"]