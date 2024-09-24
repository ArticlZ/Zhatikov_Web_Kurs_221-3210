import mysql.connector
from flask import g

class DBConnector:
    def __init__(self, app):
        self.app = app
        app.teardown_appcontext(self.close)

    def get_config(self):
        config = {
            'user': self.app.config['MYSQL_USER'],
            'password': self.app.config['MYSQL_PASSWORD'],
            'host': self.app.config['MYSQL_HOST'],
            'database': self.app.config['MYSQL_DATABASE']
        }
        return config

    def connect(self):
        if 'db' not in g:
            g.db = mysql.connector.connect(**self.get_config())
        return g.db
    
    def close(self, e=None):
        db = g.pop('db', None)

        if db is not None:
            db.close()
