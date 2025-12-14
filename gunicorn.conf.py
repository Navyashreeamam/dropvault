# gunicorn.conf.py
import sys

# Bind to all interfaces
bind = "0.0.0.0:8000"

# Number of workers
workers = 2

# Logging - IMPORTANT for Docker
accesslog = "-"  # Log to stdout
errorlog = "-"   # Log to stderr
loglevel = "info"

# Capture output from print statements
capture_output = True

# Enable stdout/stderr forwarding
enable_stdio_inheritance = True

# Disable output buffering
pythonunbuffered = True

# Timeout
timeout = 120

# Print startup message
print("🚀 Gunicorn starting with logging enabled...", flush=True)