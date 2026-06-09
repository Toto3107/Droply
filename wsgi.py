# wsgi.py — production entry point
# Gunicorn picks this up automatically: gunicorn wsgi:app
# Also works with: gunicorn relay:app
#
# WHY a separate wsgi.py:
#   relay.py has a __main__ block that parses CLI args.
#   When gunicorn imports relay.py as a module those args don't run,
#   but the module-level code (Flask app, store init) still needs to execute.
#   This file ensures the store is initialised with env var config
#   before gunicorn starts serving requests.

import os
from relay import app, _init_store, DEV_MODE

# Initialise storage once at import time (gunicorn worker startup)
import relay as _relay
_relay.store = _init_store()

# Export app for gunicorn
__all__ = ["app"]