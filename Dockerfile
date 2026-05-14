FROM python:3.13-slim

RUN groupadd --system velio && useradd --system --gid velio --no-create-home velio

WORKDIR /app

COPY sanitizer/ ./sanitizer/
COPY api/ ./api/
RUN pip install --no-cache-dir fastapi uvicorn

USER velio

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "api.app:app", "--host", "0.0.0.0", "--port", "8000"]
