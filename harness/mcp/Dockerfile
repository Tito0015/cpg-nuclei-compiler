FROM python:3.12-slim
WORKDIR /app
COPY mcp_server.py .
EXPOSE 8265
CMD ["python", "mcp_server.py", "--host", "0.0.0.0", "--port", "8265"]
