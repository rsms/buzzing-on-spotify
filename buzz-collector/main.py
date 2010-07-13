
import sys
import os
import getopt
import time
import re

import buzz

token = verification_code = buzz_client = ''

def GetLoginData():
    'Obtains login information from either the command line or by querying the user'
    global token, verification_code, buzz_client, query, position
    key = secret = ''
    if len(sys.argv[1:]):
        try:
            (opts, args) = getopt.getopt(sys.argv[1:], 'k:s:v:q:p', ['key','secret', 'vercode', 'query', 'position']) 
            if (len(args)):        raise getopt.GetoptError('bad parameter')
        except getopt.GetoptError:           
#             print '''
# Usage:    %s <-t access token> <-a verification_code>
# 
# -k (--key):        OPTIONAL, previously obtained access token key
# -s (--secret):        OPTIONAL, previously obtained access token secret
# 
# Exiting...
#             ''' % (sys.argv[0])
            sys.exit(0)
        for (opt, arg) in opts:
            if opt in ('-k', '--key'):
                key = arg
            elif opt in ('-s', '--secret'):
                secret = arg
            elif opt in ('-q', '--query'):
                query = query
            elif opt in ('-p', '--position'):
                position = position
    if ((key == '') or (secret == '')):
        token = buzz_client.fetch_oauth_request_token ('oob')
        token = buzz_client.oauth_request_token
        print '''
Please access the following URL to confirm access to Google Buzz:
%s
Once you're done enter the verification code to continue: ''' % (buzz_client.build_oauth_authorization_url(token)),
        verification_code = raw_input().strip()
        buzz_client.fetch_oauth_access_token (verification_code, token)
    else:
        buzz_client.build_oauth_access_token(key, secret)
    if (buzz_client.oauth_token_info().find('Invalid AuthSub signature') != (-1)):
        print 'Access token is invalid!!!'
        sys.exit(0)
    else:
        pass
#         print '''
# Your access token key is \'%s\', secret is \'%s\'
# Keep this data handy in case you want to reuse the session later!
# ''' % (buzz_client.oauth_access_token.key, buzz_client.oauth_access_token.secret)

def getSpotifyLink(result):
    for a in result.attachments:
        uri = a.uri
        if uri and uri.startswith('http://open.spotify.com/track/'):
            return uri
    return None

def addLink(link):
    print link

_SPOTIFY_RE = re.compile('.*(http://open.spotify.com/track/[^"]*)".*')

def main():
    """it's main..."""
    
    seen = set()
    global buzz_client, query
    query = None
    buzz_client = buzz.Client()
    buzz_client.oauth_scopes=[buzz.FULL_ACCESS_SCOPE]
    buzz_client.use_anonymous_oauth_consumer()
    GetLoginData()
    # print 'Got an access token! key: %s, secret %s' % (buzz_client.oauth_access_token.key, buzz_client.oauth_access_token.secret)
    # print 'Token info: ' + buzz_client.oauth_token_info()
    longitude='59.312783'
    latitude='18.079205'
    radius='400000000'
    buzz_query = "open.spotify.com"
    if query:
        buzz_query = "%s %s" % (buzz_query, query)
    if True:
        for result in buzz_client.search(query=buzz_query):
            # if result.geocode:
            #     print result.geocode
            #     print result.actor
            # for x in dir(result):
            #     print "%s %s" % (x, str(getattr(result, x)))
            if result.id in seen:
                continue
    #            for x in dir(result):
    #                print "%s: %s" % (x, str(getattr(result, x)))
    #            return 0
            seen.add(result.id)
            link = getSpotifyLink(result)
            if link:
                addLink(link)
                continue
            m = _SPOTIFY_RE.match(result.content)
            if m:
                addLink(m.group(1))
        time.sleep(1)
    return 0

if __name__ == '__main__':
    sys.exit(main())
