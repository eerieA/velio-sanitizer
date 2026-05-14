FROM python:3.13-slim

RUN groupadd --system velio && useradd --system --gid velio --no-create-home velio

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY sanitizer/ ./sanitizer/
COPY api/ ./api/

USER velio

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "api.app:app", "--host", "0.0.0.0", "--port", "8000"]
