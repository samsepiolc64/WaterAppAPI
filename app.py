from flask import Flask

app = Flask(__name__)

app.config.from_pyfile('./config/config.py')

from views.views import *

if __name__ == '__main__':
     app.run()