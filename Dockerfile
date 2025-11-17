# Use a supported base image (buster is EOL)
FROM python:3.10-slim-bullseye

WORKDIR /app
COPY . /app

# Install system dependencies (only if needed)
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Run your app
CMD ["python3", "app.py"]
