# Imagem oficial Python 3.11
FROM python:3.11-slim

WORKDIR /app

# Copia todos os arquivos do projeto para dentro do container
COPY . /app

# Instala dependências de sistema para SQLite e builds Python
RUN apt-get update && apt-get install -y gcc libsqlite3-dev && rm -rf /var/lib/apt/lists/*

# Instala dependências Python
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

EXPOSE 5000

# Comando de inicialização do Gunicorn apontando para o seu app Flask
CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:5000"]