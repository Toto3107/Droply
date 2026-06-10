# wsgi.py — production entry point for gunicorn
# Usage: gunicorn wsgi:app
#
# This file initialises the storage backend before gunicorn starts
# serving requests. relay.py's __main__ block (argparse / startup banner)
# does NOT run when imported as a module — only the Flask app and
# module-level code executes.

import os
import relay as _relay

# Initialise storage using env vars (Redis if REDIS_URL set, else memory)
_relay.store = _relay._init_store()

# The Flask app gunicorn serves
app = _relay.app