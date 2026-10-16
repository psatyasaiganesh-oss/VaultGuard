FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY vaultguard ./vaultguard
COPY tests ./tests

RUN python -m compileall -q vaultguard tests \
    && python -m unittest discover -v

RUN useradd --create-home --uid 10001 vaultguard
USER vaultguard

ENTRYPOINT ["python", "-m", "vaultguard"]
CMD ["demo"]
