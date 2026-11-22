FROM python:3.12-slim
LABEL org.opencontainers.image.source="https://github.com/darkmatter-sudo/postfiat-validator-installer"
# Apply the Debian security/point updates the base tag has not picked up yet (imagescan reports them as fixable).
RUN apt-get update && apt-get -y --no-install-recommends upgrade && rm -rf /var/lib/apt/lists/*
COPY pft_exporter.py /app/pft_exporter.py
USER nobody
# Inside the container it must listen on 0.0.0.0; publish only to localhost:
#   docker run --network host -e PFT_EXPORTER_ADDR=127.0.0.1 ...   (reaches admin RPC on host localhost)
ENV PFT_EXPORTER_ADDR=127.0.0.1 PFT_EXPORTER_PORT=9877
CMD ["python3", "/app/pft_exporter.py"]
