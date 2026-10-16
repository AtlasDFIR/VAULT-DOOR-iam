# VAULT-DOOR SAML service provider
# Python 3.13 matches the tested, prebuilt xmlsec and lxml packages, so no compilers are needed.
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --only-binary=:all: -r requirements.txt

COPY . .

# Run as an unprivileged user, not root.
RUN useradd --create-home --uid 10001 vault && chown -R vault:vault /app
USER vault

EXPOSE 8000
CMD ["python", "app.py"]
