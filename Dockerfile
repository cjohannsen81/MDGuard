FROM cgr.dev/chainguard/python:latest

WORKDIR /github/workspace

COPY scanner.py /github/workspace/scanner.py

ENTRYPOINT ["python", "/github/workspace/scanner.py"]
