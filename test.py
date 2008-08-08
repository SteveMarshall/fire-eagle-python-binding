import fireeagle_api
from pprint import pprint

consumer_key, consumer_secret = fireeagle_api.read_consumer_tokens()
fe = fireeagle_api.FireEagle( consumer_key, consumer_secret )

print "Getting a request token"
request_token = fe.request_token()

auth_url          = fe.authorize( request_token )
raw_input( 'Please go to the following URL and authorize the token:\n%s\n' % auth_url )

print "Exchanging the request token for an access token"
access_token        = fe.access_token( request_token )

where = 'London, England'
print "Looking up %s" % where
pprint( fe.lookup( access_token, q=where ) )

print "Asking Fire Eagle where you are"
pprint( fe.user( access_token ) )
