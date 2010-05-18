"""
Fire Eagle API Python module v0.6.1
by Steve Marshall <steve@nascentguruism.com>
                 <http://nascentguruism.com/>

Source repo at <http://github.com/SteveMarshall/fire-eagle-python-binding/>

Example usage:

>>> from fireeagle_api import FireEagle
>>> from pprint import pprint
>>> fe = FireEagle( YOUR_CONSUMER_KEY, YOUR_CONSUMER_SECRET )
>>> application_token = fe.request_token()
>>> auth_url          = fe.authorize( application_token )
>>> print auth_url
>>> pause( 'Please authorize the app at that URL!' )
>>> user_token        = fe.access_token( application_token )
>>> pprint( fe.lookup( user_token, q='London, England' ) )
[{'name': 'London, England', 'place_id': '.2P4je.dBZgMyQ'}]
>>> pprint( fe.user( user_token ) )
[   {   'best_guess': True,
        'georss:box': [   u'51.2613182068',
                          u'-0.5090100169',
                          u'51.6860313416',
                          u'0.2803600132'],
        'level': 3,
        'level_name': 'city',
        'located_at': datetime.datetime(2008, 2, 29, 13, 22, 2),
        'name': 'London, England',
        'place_id': '.2P4je.dBZgMyQ'},
    {   'best_guess': True,
        'georss:box': [   u'49.8662185669',
                          u'-6.4506998062',
                          u'55.8111686707',
                          u'1.7633299828'],
        'level': 5,
        'level_name': 'state',
        'located_at': datetime.datetime(2008, 2, 29, 13, 22, 2),
        'name': 'England, United Kingdom',
        'place_id': 'pn4MsiGbBZlXeplyXg'},
    {   'best_guess': True,
        'georss:box': [   u'49.1620903015',
                          u'-8.6495599747',
                          u'60.8606987',
                          u'1.7633399963'],
        'level': 6,
        'level_name': 'country',
        'located_at': datetime.datetime(2008, 2, 29, 13, 22, 2),
        'name': 'United Kingdom',
        'place_id': 'DevLebebApj4RVbtaQ'}]

Copyright (c) 2008, Steve Marshall
All rights reserved.

Unless otherwise specified, redistribution and use of this software in
source and binary forms, with or without modification, are permitted
provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * The name of the author nor the names of any contributors may be
      used to endorse or promote products derived from this software without
      specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""
import datetime, httplib, os.path, re, string
from xml.dom import minidom

import oauth

# General API setup
API_PROTOCOL = 'https'
API_SERVER   = 'fireeagle.yahooapis.com'
API_VERSION  = '0.1'
FE_PROTOCOL  = 'https'
FE_SERVER    = 'fireeagle.yahoo.net'

# Calling templates
API_URL_TEMPLATE   = string.Template(
    '${server}/api/' + API_VERSION + '/${method}'
)
OAUTH_URL_TEMPLATE = string.Template(
    '${server}/oauth/${method}'
)
AUTHORIZE_URL_TEMPLATE = string.Template(
    '${server}/oauth/${method}?oauth_token=${token}'
)
POST_HEADERS = {
    'Content-type': 'application/x-www-form-urlencoded',
    'Accept'      : 'text/plain'
}
LOCATION_PARAMETERS = [
    'address', 'cid', 'city', 'country', 'geom', 'lac', 'lat',
    'lon', 'mcc', 'mnc', 'place_id', 'postal', 'q', 'state', 'woeid'
]

# Error templates
NULL_ARGUMENT_EXCEPTION    = string.Template(
    'Too few arguments were supplied for the method ${method}; required arguments are: ${args}'
)
# TODO: Allow specification of method name and call-stack?
SPECIFIED_ERROR_EXCEPTION   = string.Template(
    '${message} (Code ${code})'
)
UNSPECIFIED_ERROR_EXCEPTION = string.Template(
    'An error occurred whilst trying to execute the requested method, and the server responded with status ${status}.'
)

# Attribute conversion functions
string  = lambda s: s.encode('utf8')
boolean = lambda s: 'true' == s.lower()

def geo_str(s):
    if 0 == len(s):
        return None
    # TODO: Would this be better served returning an array of floats?
    return [float(bit) for bit in s.split(' ')]

def date(s):
    # 2008-02-08T10:49:03-08:00
    bits = re.match(r"""
        ^(\d{4}) # Year          ($1)
        -(\d{2}) # Month         ($2)
        -(\d{2}) # Day           ($3)
        T(\d{2}) # Hour          ($4)
        :(\d{2}) # Minute        ($5)
        :(\d{2}) # Second        ($6)
        [+-]   # TODO: TZ offset dir ($7)
        \d{2}  # TODO: Offset hour   ($8)
        :\d{2} # TODO: Offset min    ($9)
    """, s, re.VERBOSE
    ).groups()
    bits = [bit for bit in bits if bit is not None]
    
    # TODO: Generate fixed-offset tzinfo
    return datetime.datetime(*map(int, bits))

# Return types
LOCATION = 'location', {
    'name'    : string,
    'place_id': string,
    'woeid'   : string,
}

USER_LOCATION = 'location', {
    'best_guess'   : boolean,
    # HACK: I'm not entirely happy using 'georss:box' as the key here
    'georss:box'   : geo_str,
    'georss:point' : geo_str,
    'level'        : int,
    'level_name'   : string,
    'located_at'   : date,
    'name'         : string,
    'place_id'     : string,
    'woeid'        : string,
    'query'        : string,
}

USER = 'user', {
    'token'   : string,
    'location': USER_LOCATION,
}
FIREEAGLE_METHODS = {
    # OAuth methods
    'access_token': {
        'http_headers': None,
        'http_method' : 'GET',
        'optional'    : [],
        'required'    : ['oauth_verifier', 'token'],
        'returns'     : 'oauth_token',
        'url_template': OAUTH_URL_TEMPLATE,
    },
    'authorize': {
        'http_headers': None,
        'http_method' : 'GET',
        'optional'    : [],
        'required'    : ['token'],
        'returns'     : 'request_url',
        'url_template': AUTHORIZE_URL_TEMPLATE,
    },
    'request_token': {
        'http_headers': None,
        'http_method' : 'GET',
        'optional'    : ['oauth_callback'],
        'required'    : [],
        'returns'     : 'oauth_token',
        'url_template': OAUTH_URL_TEMPLATE,
    },
    # Fire Eagle methods
    'lookup': {
        'http_headers': None,
        'http_method' : 'GET',
        'optional'    : LOCATION_PARAMETERS,
        'required'    : ['token'],
        'returns'     : LOCATION,
        'url_template': API_URL_TEMPLATE,
    },
    'recent': {
        'http_headers': None,
        'http_method' : 'GET',
        'optional'    : ['per_page', 'page', 'time'],
        'required'    : ['token'],
        'returns'     : USER,
        'url_template': API_URL_TEMPLATE,
    },
    'update': {
        'http_headers': POST_HEADERS,
        'http_method' : 'POST',
        'optional'    : LOCATION_PARAMETERS,
        'required'    : ['token'],
        # We don't care about returns from update: HTTP 200 is success
        'returns'     : None,
        'url_template': API_URL_TEMPLATE,
    },
    'user': {
        'http_headers': None,
        'http_method' : 'GET',
        'optional'    : [],
        'required'    : ['token'],
        'returns'     : USER,
        'url_template': API_URL_TEMPLATE,
    },
    'within': {
        'http_headers': None,
        'http_method' : 'GET',
        # HACK: woe_id is ignored if place_id is present, so neither is
        #       strictly 'required'. Unfortunately, calling with neither
        #       returns an empty list
        'optional'    : ['place_id', 'woe_id'],
        'required'    : ['token'],
        'returns'     : USER,
        'url_template': API_URL_TEMPLATE,
    }
}

class FireEagleException( Exception ):
    pass

# Used as a proxy for methods of the FireEagle class; when methods are called,
# __call__ in FireEagleAccumulator is called, ultimately calling the
# fireeagle_obj's callMethod()
class FireEagleAccumulator:
    def __init__( self, fireeagle_obj, name ):
        self.fireeagle_obj = fireeagle_obj
        self.name          = name
    
    def __repr__( self ):
        return self.name
    
    def __call__( self, *args, **kw ):
        return self.fireeagle_obj.call_method( self.name, *args, **kw )
    

class FireEagle:
    def __init__( self, rc_or_consumer_key, consumer_secret=None ):
        """
        syntax: FireEagle( os.path.expanduser( "~/.fireeaglerc" ) )
        or FireEagle( CONSUMER_KEY, CONSUMER_SECRET )
        """

        # Prepare object lifetime variables
        self.read_config( rc_or_consumer_key, consumer_secret )            
        self.oauth_consumer   = oauth.OAuthConsumer(
            self.consumer_key, 
            self.consumer_secret
        )
        self.signature_method = oauth.OAuthSignatureMethod_HMAC_SHA1()
        proto, host, port = re.search(r"^(https?)://([a-z\.0-9]+)(?:\:(\d+))?$", self.api_server).groups()
        self.http_connection = (proto == 'https' and httplib.HTTPSConnection or httplib.HTTPConnection)( host, port )
        
        # Prepare the accumulators for each method
        for method, _ in FIREEAGLE_METHODS.items():
            if not hasattr( self, method ):
                setattr( self, method, FireEagleAccumulator( self, method ))

    def read_config( self, rc_or_consumer_key, consumer_secret ):
        if consumer_secret is None:
            info = {}
            for line in open( rc_or_consumer_key ).readlines():
                p = line.find( "#" )
                if p != -1: line = line[:p]
                line = line.strip()
                if not line: continue
                k, v = line.split("=", 1)
                info[ k.strip() ] = v.strip()
        else:
            info = {
                'consumer_key': rc_or_consumer_key,
                'consumer_secret': consumer_secret,
                }

        info.setdefault("api_server", API_SERVER)
        info.setdefault("api_protocol", API_PROTOCOL)
        self.api_server = self._build_server_url(info, 'api')

        info.setdefault("auth_server", FE_SERVER)
        info.setdefault("auth_protocol", FE_PROTOCOL)
        self.auth_server = self._build_server_url(info, 'auth')

        self.consumer_key, self.consumer_secret = info['consumer_key'], info['consumer_secret']

    def _build_server_url( self, info, role ):
        proto = info['%s_protocol' % role]
        default_port = (proto == 'https') and 443 or 80
        port = int(info.get('%s_port' % role, default_port))
        url = '%s://%s%s' % (
            proto,
            info['%s_server' % role],
            (port != default_port) and (':%d' % port) or '',
            )
        return url
    
    def fetch_response( self, http_method, url, \
            body = None, headers = {}):
        """Pass a request to the server and return the response as a string"""
        # Explicity add a host header to prevent Python pre2.6 from adding the port
        headers['host'] = API_SERVER
        # Prepare the request
        if ( body is not None ) or ( headers is not None ):
            self.http_connection.request( http_method, url, body, headers )
        else:
            self.http_connection.request( http_method, url )
        
        # Get the response
        response      = self.http_connection.getresponse()
        response_body = response.read()
        
        # If we've been informed of an error, raise it
        if ( 200 != response.status ):
            # Try to get the error message
            try:
                error_dom       = minidom.parseString( response_body )
                response_errors = error_dom.getElementsByTagName( 'err' )
            except: # TODO: Naked except: make this explicit!
                response_errors = None
            
            # If we can't get the error message, just raise a generic one
            if response_errors:
                msg = SPECIFIED_ERROR_EXCEPTION.substitute( \
                    message = response_errors[0].getAttribute( 'msg' ),
                    code    = response_errors[0].getAttribute( 'code' )
                )
            else:
                msg = UNSPECIFIED_ERROR_EXCEPTION.substitute( \
                    status = response.status )
            
            raise FireEagleException, msg
        
        # Return the body of the response
        return response_body
    
    def build_return( self, dom_element, target_element_name, conversions):
        results = []
        for node in dom_element.getElementsByTagName( target_element_name ):
            data = {}
            
            for key, conversion in conversions.items():
                node_key      = key.replace( '_', '-' )
                key           = key.replace( ':', '_' )
                data_elements = node.getElementsByTagName( node_key )
                
                # If conversion is a tuple, call build_return again
                if isinstance( conversion, tuple ):
                    child_element, child_conversions = conversion
                    data[key] = self.build_return( \
                        node, child_element, child_conversions \
                    )
                else:
                    # If we've got multiple elements, build a 
                    # list of conversions
                    if data_elements and ( len( data_elements ) > 1 ):
                        data_item = []
                        for data_element in data_elements:
                            data_item.append( conversion(
                                data_element.firstChild.data
                            ) )
                    # If we only have one element, assume text node
                    elif data_elements:
                        data_item = conversion( \
                            data_elements[0].firstChild.data
                        )
                    # If no elements are matched, convert the attribute
                    else:
                        data_item = conversion( \
                            node.getAttribute( node_key ) \
                        )
                    
                    if data_item is not None:
                        data[key] = data_item
            
            results.append( data )
        
        return results
    
    def call_method( self, method, *args, **kw ):
        
        # Theoretically, we might want to do 'does this method exits?' checks
        # here, but as all the aggregators are being built in __init__(),
        # we actually don't need to: Python handles it for us.
        meta = FIREEAGLE_METHODS[method]
        
        if args:
            # Positional arguments are mapped to meta['required'] 
            # and meta['optional'] in order of specification of those
            # (with required first, obviously)
            names = meta['required'] + meta['optional']
            for i in range( len( args ) ):
                kw[names[i]] = args[i]
        
        # Check we have all required arguments
        if len( set( meta['required'] ) - set( kw.keys() ) ) > 0:
            raise FireEagleException, \
                NULL_ARGUMENT_EXCEPTION.substitute( \
                    method = method, \
                    args   = ', '.join( meta['required'] )
                )
        
        # Token shouldn't be handled as a normal arg, so strip it out
        # (but make sure we have it, even if it's None)
        if 'token' in kw:
            token = kw['token']
            del kw['token']
        else:
            token = None

        # If the return type is the request_url, simply build the URL
        # (without a signature) and return it witout executing
        # anything.
        if 'request_url' == meta['returns']:
            return meta['url_template'].substitute( method=method, server=self.auth_server, token=token.key )

        if 'oauth_callback' in meta['optional'] and 'oauth_callback' not in kw:
            kw['oauth_callback'] = "oob"

        # Build and sign the oauth_request
        # NOTE: If ( token == None ), it's handled silently
        #       when building/signing
        oauth_request = oauth.OAuthRequest.from_consumer_and_token(
            self.oauth_consumer,
            token       = token,
            http_method = meta['http_method'],
            http_url    = meta['url_template'].substitute( method=method, server=self.api_server ),
            parameters  = kw
        )
        oauth_request.sign_request(
            self.signature_method,
            self.oauth_consumer,
            token
        )
        
        if 'POST' == meta['http_method']:
            response = self.fetch_response( oauth_request.http_method, \
                meta['url_template'].substitute( method=method, server=""), \
                oauth_request.to_postdata(), \
                meta['http_headers'] )
        else:
            response = self.fetch_response( oauth_request.http_method, \
                meta['url_template'].substitute( method=method, server="") + "?" + oauth_request.to_postdata() )
        
        # Method returns nothing, but finished fine
        if not meta['returns']:
            return True
        # Return the oauth token
        elif 'oauth_token' == meta['returns']:
            return oauth.OAuthToken.from_string( response )
        
        element, conversions = meta['returns']
        response_dom         = minidom.parseString( response )
        
        results              = self.build_return( \
            response_dom, element, conversions )
        
        return results
    

# TODO: Cached version
