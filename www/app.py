import os
from flask import Flask
from flask_mwoauth import MWOAuth
from mwoauth import ConsumerToken, Handshaker
from builtins import input

app = Flask(__name__)

# Generate a random secret application key
# 
# NOTE: this key changes every invocation. In an actual application, the key
# should not change! Otherwise you might get a different secret key for
# different requests, which means you can't read data stored in cookies,
# which in turn breaks OAuth.
#
# So, for an actual application, use app.secret_key = "some long secret key"
# (which you could generate using os.urandom(24))
#
app.secret_key = '@\xad\x80q\xd7;\xbf6\xe4\xcc1\xc9\xee6j\x10\xdfb"\x15^^\x04\xc5'

print("""
NOTE: The callback URL you entered when proposing an OAuth consumer
probably did not match the URL under which you are running this development
server. Your redirect back will therefore fail -- please adapt the URL in
your address bar to http://localhost:5000/oauth-callback?oauth_verifier=...etc
""")

consumer_key = '40a96777692df4ea05c5c8c9f3029f76'
consumer_secret = '0a3049327205710a1e921ac87e31bf57a38783d6'

mwoauth = MWOAuth(consumer_key=consumer_key, consumer_secret=consumer_secret)
app.register_blueprint(mwoauth.bp)

@app.route("/")
def index():
#   consumer_token = ConsumerToken(consumer_key, consumer_secret)
#   handshaker = Handshaker("https://en.wikipedia.org/w/index.php", consumer_token)
#   identity = handshaker.identify(access_token)
#   oauth = mwoauth
#   return oauth
#   return identify
    return "logged in as: " + repr(mwoauth.get_current_user(False)) + "<br>" + \
           "<a href=login>login</a> / <a href=logout>logout</a>"

if __name__ == "__main__":
    app.run(debug=True)
