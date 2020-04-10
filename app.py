from flask import Flask
from flask_cors import CORS

import sys
sys.path.append("./views")
sys.path.append("./config")

app = Flask(__name__)
CORS(app)
app.config.from_pyfile('./config/config.py')

from config.create_database import *

from views.views import *

if __name__ == '__main__':
     app.run()