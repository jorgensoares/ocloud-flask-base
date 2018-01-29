#!/usr/bin/python
from web.functions import sigterm_handler
from web import app
import signal


def main():
    signal.signal(signal.SIGTERM, sigterm_handler)
    app.run(host='0.0.0.0',
            port=8080,
            threaded=True,
            )

if __name__ == "__main__":
    main()
