import logging

from werkzeug import serving


class FlaskLogHandler(serving.WSGIRequestHandler):
    def __init__(self, *args):
        """
         Set logger and super class __init__ to avoid logging. getLogger (... ) in Flask 1.
        """
        self.logger = logging.getLogger("flask")
        super().__init__(*args)

    def log(self, levelname, message, *args):
        """
         Log a message to the log. This is a wrapper around the logging module's log () method to allow us to specify the level of the message as well as the status code ( 200 304 etc. )
         
         @param levelname - The name of the log level
         @param message - The message to log
        """
        msg = args[0]
        code = int(args[1])

        # Set levelname type and levelname to debug
        if code in [200, 304]:
            levelname = "debug"
            # type = "debug"

        # Set the logging level to info debug
        if levelname == "info":
            levelno = logging.INFO
        elif levelname == "debug":
            levelno = logging.DEBUG
        else:
            raise Exception("Unknown level " + type)
        self.logger.log(levelno, f"{code} ({self.address_string()}): {msg}")
