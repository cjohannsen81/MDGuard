FROM cgr.dev/chainguard/python:latest

# Workdir must match the mount path
WORKDIR /github/workspace

# Copy only the scanner (optional, in case GitHub mount overwrites)
COPY scanner.py /github/workspace/scanner.py

ENTRYPOINT ["python", "/github/workspace/scanner.py"]
