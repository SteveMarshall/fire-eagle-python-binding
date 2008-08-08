import fireeagle_api
import os.path
from pprint import pprint

"""

First, paste your consumer key and secret into ~/.fireeaglerc, in the following format:

consumer_key = YNqmPYEMEOzA
consumer_secret = 7W6t7UwHXhe7UtAVo2KO5VGbK6I1UjOS

"""

fe = fireeagle_api.FireEagle( os.path.expanduser( '~/.fireeaglerc' ) )

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
