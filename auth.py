from flask import Flask, request, make_response, render_template
from mwoauth import ConsumerToken, Handshaker
from six.moves import input # For compatibility between python 2 and 3
import redis
import string
import random
import sys
import pickle

sys.path.insert(0, ".")

r = redis.Redis(
    host='tools-redis',
    port=6379)

def id_generator(size=20, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

app = Flask(__name__)
# Consruct a "consumer" from the key/secret provided by MediaWiki
import config
consumer_token = ConsumerToken(config.consumer_key, config.consumer_secret)

@app.route('/auth')
def auth():
    # Construct handshaker with wiki URI and consumer
    handshaker = Handshaker("https://en.wikipedia.org/w/index.php", consumer_token)
    
    # Step 1: Initialize -- ask MediaWiki for a temporary key/secret for user
    redirect, request_token = handshaker.initiate()
    
    # Make a response
    resp = make_response(render_template('redirect.html'), 302)
    resp.headers['Location'] = redirect
    # Generate a random key for redis
    rediskey = config.redisprefix + id_generator()
    # Pickle the request_token object and store it in redis
    serialrequest_token = pickle.dumps(request_token)
    r.set(rediskey, serialrequest_token)
    # Set a cookie containing the redis key
    resp.set_cookie('rediskey', rediskey)
    # Return the response
    return resp

#response_qs = input("Response query string: ")
@app.route('/')
def authcallback():
    # Step 3: Complete -- obtain authorized key/secret for "resource owner"
    rediskey = request.cookies.get('rediskey')
    oauth_verifier = request.args.get('oauth_verifier', '')
    oauth_token = request.args.get('oauth_token', '')
    request_token = r.get(rediskey)
    if request_token == None:
        resp = make_response(render_template('redirect.html'), 302)
        resp.headers['Location'] = 'auth'
        return resp
    elif oauth_verifier == '':
        resp = make_response(render_template('redirect.html'), 302)
        resp.headers['Location'] = 'auth'
        return resp
    else:
        handshaker = Handshaker("https://en.wikipedia.org/w/index.php", consumer_token)
        serialrequest_token = r.get(rediskey)
        request_token = pickle.loads(serialrequest_token)
        response_qs = 'oauth_verifier=' + oauth_verifier + '&' + 'oauth_token=' + oauth_token
        #print(request_token)
        #print(response_qs)
        access_token = handshaker.complete(request_token,response_qs)
        #print(str(access_token))
        
        # Step 4: Identify -- (optional) get identifying information about the user
        identity = handshaker.identify(access_token)
        r.delete(rediskey)
        #return "Identified as {username}.".format(**identity)
        username = "{username}".format(**identity)
        resp = make_response(render_template('redirect.html'), 302)
        resp.headers['Location'] = 'https://kiwiirc.com/client/irc.freenode.net/wikipedia-en-help?nick=' + username
        return resp

if __name__ == '__main__':
   app.run(debug=True)
