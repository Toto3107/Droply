FROM python:3.12-slim

WORKDIR /app

# Install deps first (cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY relay.py .
COPY templates/ templates/
COPY static/ static/

# Create logs dir
RUN mkdir -p logs

# Non-root user for security
RUN useradd -m droply && chown -R droply:droply /app
USER droply

EXPOSE 8080

CMD ["gunicorn", "relay:app", \
     "--bind", "0.0.0.0:8080", \
     "--workers", "2", \
     "--worker-class", "gthread", \
     "--threads", "4", \
     "--timeout", "120", \
     "--log-level", "info", \
     "--access-logfile", "-"]