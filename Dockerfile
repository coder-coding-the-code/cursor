FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY openfga ./openfga
RUN pip install --no-cache-dir .
EXPOSE 8080
CMD ["python", "-m", "guardian_trust", "serve", "--host", "0.0.0.0", "--port", "8080"]
