# AgentGate on Render: broker + OpenFGA in one container (OpenFGA on Postgres when FGA_DB_PASSWORD is set).
# Build context = repo root:  docker build -f deploy/render/Dockerfile .
ARG OPENFGA_VERSION=v1.22.1
FROM openfga/openfga:${OPENFGA_VERSION} AS openfga

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY --from=openfga /openfga /usr/local/bin/openfga

WORKDIR /srv/broker
COPY broker/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt pyyaml

COPY broker/ /srv/broker/
COPY policy/model.json policy/tuples.yaml /srv/policy/
COPY deploy/render/seed_fga.py deploy/render/fga_db.py deploy/render/start.sh /srv/deploy/
RUN sed -i "s/\r$//" /srv/deploy/start.sh && chmod +x /srv/deploy/start.sh && useradd --uid 10001 --no-create-home agentgate
USER agentgate

CMD ["/srv/deploy/start.sh"]
