FROM cgr.dev/chainguard/python:latest

WORKDIR /app
COPY scanner.py /app/scanner.py

ENTRYPOINT ["python", "/app/scanner.py"]