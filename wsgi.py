# wsgi.py — gunicorn entry point
#
# relay.py now initialises `store` at module level (not in main()),
# so every gunicorn worker gets a working store the moment it imports this.
# No extra init needed here — just expose the app.

from relay import app  # noqa: F401  