FROM --platform=linux/amd64 python:3.11-slim-buster

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["fastapi", "dev", "main.py", "--host", "0.0.0.0"]

EXPOSE 8000