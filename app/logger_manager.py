import logging
from logging.handlers import TimedRotatingFileHandler

class LoggerManager:
    def __init__(self, app):
        log_file_path = 'application.log'
        handler = TimedRotatingFileHandler(log_file_path, when='midnight', interval=1, backupCount=7)
        handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        app.logger.addHandler(handler)
        app.logger.setLevel(logging.DEBUG)