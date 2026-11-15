# Demo agents + orchestrator. Run with: docker compose run --rm agents pay
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv
COPY requirements.txt /srv/agents/requirements.txt
RUN pip install --no-cache-dir -r /srv/agents/requirements.txt
COPY . /srv/agents/
ENTRYPOINT ["python", "-m", "agents.orchestrator"]
