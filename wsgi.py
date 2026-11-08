"""WSGI entry point.

Development:  flask --app wsgi run
Production:   gunicorn -c gunicorn.conf.py wsgi:app
"""

from serverpilot import create_app

app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
