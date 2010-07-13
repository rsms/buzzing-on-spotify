# Copyright 2010 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Common Tasks
============
- Authentication
  - Getting the request token::
    import buzz
    client = buzz.Client()
    client.build_oauth_consumer('your-app.appspot.com', 'consumer_secret')
    client.oauth_scopes.append(buzz.FULL_ACCESS_SCOPE)
    request_token = \\
      client.fetch_oauth_request_token('http://example.com/callback/')
    # Persist the request_token
    authorization_url = client.build_oauth_authorization_url()
    self.redirect(authorization_url)
  - Exchanging a request token for an access token::
    import buzz
    client = buzz.Client()
    client.build_oauth_consumer('your-app.appspot.com', 'consumer_secret')
    client.oauth_scopes.append(buzz.FULL_ACCESS_SCOPE)
    # Retrieve the persisted request token
    client.build_oauth_request_token(
      request_token.key, request_token.secret
    )
    verifier = self.request.get('oauth_verifier')
    access_token = \\
      client.fetch_oauth_access_token(verifier)
    # Persist the access_token
  - Reusing an access token::
    import buzz
    client = buzz.Client()
    client.build_oauth_consumer('your-app.appspot.com', 'consumer_secret')
    client.oauth_scopes.append(buzz.FULL_ACCESS_SCOPE)
    # Retrieve the persisted access token
    client.build_oauth_access_token(
      access_token.key, access_token.secret
    )
- Creating a post
  - Simple::
    post = buzz.Post(
      content="This is some example content."
    )
    client.create_post(post)
  - Post with a link::
    attachment = buzz.Attachment(
      type='article',
      title='Google Buzz',
      uri='http://www.google.com/buzz'
    )
    post = buzz.Post(
      content="Google Buzz is really cool.",
      attachments=[attachment]
    )
    client.create_post(post)
  - Post with a geocode::
    post = buzz.Post(
      content="Google Buzz is really cool.",
      geocode=('37.421776', '-122.084155')
    )
    client.create_post(post)
"""

import os
import sys
import urlparse
import cgi
import httplib
import string
import urllib
import re

import logging

sys.path.append(os.path.join(os.path.dirname(__file__), 'third_party'))

try:
  import oauth.oauth as oauth
except (ImportError):
  import oauth

try:
  # This is where simplejson lives on App Engine
  from django.utils import simplejson
except (ImportError):
  import simplejson

CONFIG_PATH = os.environ.get('BUZZ_CONFIG_PATH', 'buzz_python_client.yaml')
if os.path.exists(CONFIG_PATH):
  # Allow optional configuration file to be loaded
  try:
    import yaml
  except (ImportError):
    sys.stderr.write('Please install PyYAML.\n')
    exit(1)
  CLIENT_CONFIG = yaml.load(open(CONFIG_PATH).read())
  API_PREFIX = CLIENT_CONFIG.get('api_prefix') or \
    "https://www.googleapis.com/buzz/v1"
else:
  CLIENT_CONFIG = {}
  API_PREFIX = "https://www.googleapis.com/buzz/v1"

READONLY_SCOPE = 'https://www.googleapis.com/auth/buzz.readonly'
FULL_ACCESS_SCOPE = 'https://www.googleapis.com/auth/buzz'

OAUTH_REQUEST_TOKEN_URI = \
  'https://www.google.com/accounts/OAuthGetRequestToken'
OAUTH_ACCESS_TOKEN_URI = \
  'https://www.google.com/accounts/OAuthGetAccessToken'
OAUTH_AUTHORIZATION_URI = \
  'https://www.google.com/buzz/api/auth/OAuthAuthorizeToken'

class RetrieveError(Exception):
  """
  This exception gets raised if there was some kind of HTTP or network error
  while accessing the API.
  """
  def __init__(self, message=None, uri=None, json=None, exception=None):
    if not message and exception:
      message = str(exception)
    self._uri = uri
    self._message = message
    self._json = json

  def __str__(self):
    return 'Could not retrieve \'%s\': %s' % (self._uri, self._message)

class JSONParseError(Exception):
  """
  This exception gets raised if the API sends data that does not match
  what the client was expecting.  If this exception is raised, it's typically
  a bug.
  """
  def __init__(self, message=None, json=None, uri=None, exception=None):
    if not message and exception:
      message = str(exception)
    self._message = message
    self._uri = uri
    self._json = json
    self._exception = exception

  def __str__(self):
    if self._uri:
      if self._exception and isinstance(self._exception, KeyError):
        return 'Parse failed for \'%s\': KeyError(%s) on %s' % (
          self._uri, str(self._exception), self._json
        )
      else:
        return 'Parse failed for \'%s\': %s' % (self._uri, self._json)
    else:
      if self._exception and isinstance(self._exception, KeyError):
        return 'Parse failed: KeyError(%s) on %s' % (
          str(self._exception), self._json
        )
      else:
        return 'Parse failed: %s' % (self._json)

def _prune_json_envelope(json):
  # Follow Postel's law
  if isinstance(json, dict):
    if isinstance(json, dict) and json.get('data'):
      json = json['data']
    if isinstance(json, dict) and json.get('entry'):
      json = json['entry']
    if isinstance(json, dict) and json.get('results'):
      json = json['results']
    if isinstance(json, dict) and json.get('items'):
      json = json['items']
  else:
    raise TypeError('Expected dict: \'%s\'' % str(json))
  return json

def _parse_geocode(geocode):
  # Follow Postel's law
  if ' ' in geocode:
    lat, lon = geocode.split(' ')
  elif ',' in geocode:
    lat, lon = geocode.split(',')
  else:
    raise ValueError('Bogus geocode.')
  return (lat, lon)

class Client:
  """
  The L{Client} object is the primary method of making calls against the Buzz
  API.  It can be used with or without authentication.  It attempts to reuse
  HTTP connections whenever possible.  Currently, authentication is done via
  OAuth.  
  """
  def __init__(self):
    # Make sure we're always getting the right HTTP connection, even if
    # API_PREFIX changes
    parsed = urlparse.urlparse(API_PREFIX)
    authority = parsed[1].split(':')
    if len(authority) == 1:
      # Incidentally, this is why unpacking shouldn't complain about
      # size mismatch on the array.  Bad Python.  Stop trying to protect me!
      self._host = authority[0]
      self._port = None
    else:
      self._host, self._port = authority
    if not self._port:
      if parsed[0] == 'https':
        self._port = 443
      else:
        self._port = 80

    self._http_connection = None

    # OAuth state
    self.oauth_scopes = []
    self._oauth_http_connection = None
    self.oauth_consumer = None
    self.oauth_request_token = None
    self.oauth_access_token = None
    self.oauth_display_name = None
    self._oauth_token_authorized = False
    self._oauth_signature_method_hmac_sha1 = \
      oauth.OAuthSignatureMethod_HMAC_SHA1()

  @property
  def http_connection(self):
    # if not self._http_connection:
    #   self._http_connection = httplib.HTTPSConnection('www.google.com')
    if not self._http_connection:
      if self._port == 443:
        self._http_connection = httplib.HTTPSConnection(self._host)
      elif self._port == 80:
        self._http_connection = httplib.HTTPConnection(self._host)
      else:
        self._http_connection = httplib.HTTPConnection(self._host, self._port)
    return self._http_connection

  def use_anonymous_oauth_consumer(self, oauth_display_name=None):
    """
    This method sets the consumer key and secret to 'anonymous'.  It can also
    optionally set the C{xoauth_displayname} parameter.  This method is
    primarily intended for use with installed applications.
    
    @type oauth_display_name: string
    @param oauth_display_name: The display name for the application
    """
    self.oauth_consumer = oauth.OAuthConsumer('anonymous', 'anonymous')
    if oauth_display_name:
      self.oauth_display_name = oauth_display_name

  def build_oauth_consumer(self, key, secret):
    """
    This method sets the consumer key and secret.  If you do not already have
    them, these can be obtained by U{registering your web application <
    http://code.google.com/apis/accounts/docs/RegistrationForWebAppsAuto.html
    >}.

    @type key: string
    @param key: Your consumer key.  This will be your hostname.
    @type secret: string
    @param secret: Your consumer secret.  This is issued to you by Google.
    """
    self.oauth_consumer = oauth.OAuthConsumer(key, secret)

  def build_oauth_request_token(self, key, secret):
    """
    This method sets the request token key and secret.  This allows you to
    load a request token into the client from persistent storage.

    @type key: string
    @param key: The request token key.
    @type secret: string
    @param secret: The request token secret.
    """
    self.oauth_request_token = oauth.OAuthToken(key, secret)

  def build_oauth_access_token(self, key, secret):
    self.oauth_access_token = oauth.OAuthToken(key, secret)

  @property
  def oauth_http_connection(self):
    if not self._oauth_http_connection:
      self._oauth_http_connection = httplib.HTTPSConnection('www.google.com')
    if self._oauth_http_connection.host != 'www.google.com':
      raise ValueError("OAuth HTTPS Connection must be for 'www.google.com'.")
    # if self._oauth_http_connection.port != 443:
    #   raise ValueError("OAuth HTTPS Connection must be for port 443.")
    return self._oauth_http_connection

  def fetch_oauth_response(self, oauth_request):
    """Sends a signed request to Google's Accounts API."""
    # Transmit the OAuth request to Google
    if oauth_request.http_method != 'POST':
      raise ValueError("OAuthRequest HTTP method must be POST.")
    try:
      self.oauth_http_connection.request(
        oauth_request.http_method,
        oauth_request.http_url,
        body=oauth_request.to_postdata(),
        headers={
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      )
      response = self.oauth_http_connection.getresponse()
    except (httplib.BadStatusLine, httplib.CannotSendRequest):
      # Reset the connection
      if self._oauth_http_connection:
        self._oauth_http_connection.close()
      self._oauth_http_connection = None
      # Retry once
      self.oauth_http_connection.request(
        oauth_request.http_method,
        oauth_request.http_url,
        body=oauth_request.to_postdata(),
        headers={
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      )
      response = self.oauth_http_connection.getresponse()
    return response

  def fetch_oauth_request_token(self, callback_uri):
    """Obtains an OAuth request token from Google's Accounts API."""
    if not self.oauth_request_token:
      # Build and sign an OAuth request
      parameters = {
        'oauth_consumer_key': self.oauth_consumer.key,
        'oauth_timestamp': oauth.generate_timestamp(),
        'oauth_nonce': oauth.generate_nonce(),
        'oauth_version': oauth.OAuthRequest.version,
        'oauth_callback': callback_uri,
        'scope': ' '.join(self.oauth_scopes)
      }
      if self.oauth_display_name:
        parameters['xoauth_displayname'] = self.oauth_display_name
      oauth_request = oauth.OAuthRequest(
        'POST',
        OAUTH_REQUEST_TOKEN_URI,
        parameters
      )
      oauth_request.sign_request(
        self._oauth_signature_method_hmac_sha1,
        self.oauth_consumer,
        token=None
      )
      response = self.fetch_oauth_response(oauth_request)
      if response.status == 200:
        # Create the token from the response
        self.oauth_request_token = oauth.OAuthToken.from_string(
          response.read()
        )
      else:
        raise Exception('Failed to obtain request token:\n' + response.read())
    return self.oauth_request_token

  def build_oauth_authorization_url(self, token=None):
    if not token:
      token = self.oauth_request_token
    if not self.oauth_consumer:
      raise ValueError("Client is missing consumer.")
    auth_uri = OAUTH_AUTHORIZATION_URI + \
      "?oauth_token=" + token.key + \
      "&domain=" + self.oauth_consumer.key + \
      "&scope=" + '%20'.join(self.oauth_scopes)
    return auth_uri

  def fetch_oauth_access_token(self, verifier=None, token=None):
    """Obtains an OAuth access token from Google's Accounts API."""
    if not self.oauth_access_token:
      if not token:
        token = self.oauth_request_token
      if not token:
        raise ValueError("A request token must be supplied.")
      # Build and sign an OAuth request
      parameters = {
        'oauth_consumer_key': self.oauth_consumer.key,
        'oauth_timestamp': oauth.generate_timestamp(),
        'oauth_nonce': oauth.generate_nonce(),
        'oauth_version': oauth.OAuthRequest.version,
        'oauth_token': token.key,
        'oauth_verifier': verifier
      }
      oauth_request = oauth.OAuthRequest(
        'POST',
        OAUTH_ACCESS_TOKEN_URI,
        parameters
      )
      oauth_request.sign_request(
        self._oauth_signature_method_hmac_sha1,
        self.oauth_consumer,
        token=token
      )
      response = self.fetch_oauth_response(oauth_request)
      if response.status == 200:
        # Create the token from the response
        self.oauth_access_token = oauth.OAuthToken.from_string(
          response.read()
        )
      else:
        raise Exception('Failed to obtain access token:\n' + response.read())
    return self.oauth_access_token

  def build_oauth_request(self, http_method, http_uri):
    # Query parameters have to be signed, and the OAuth library isn't smart
    # enough to do this automatically
    query = urlparse.urlparse(http_uri)[4] # Query is 4th element of the tuple
    if query:
      qs_parser = None
      if hasattr(urlparse, 'parse_qs'):
        qs_parser = urlparse.parse_qs
      else:
        # Deprecated in 2.6
        qs_parser = cgi.parse_qs
      # Buzz gives non-strict conforming next uris, like:
      # https://www.googleapis.com/buzz/v1/activities/search?q&lon=1123&lat=456&max-results=2&c=2
      parameters = qs_parser(
        query,
        keep_blank_values=True,
        strict_parsing=False
      )
      for k, v in parameters.iteritems():
        parameters[k] = v[0]
    else:
      parameters = {}
    # Build the OAuth request, add in our parameters, and sign it
    oauth_request = oauth.OAuthRequest.from_consumer_and_token(
      self.oauth_consumer,
      token=self.oauth_access_token,
      http_method=http_method,
      http_url=http_uri,
      parameters=parameters
    )
    oauth_request.sign_request(
      self._oauth_signature_method_hmac_sha1,
      self.oauth_consumer,
      token=self.oauth_access_token
    )
    return oauth_request

  def fetch_api_response(self, http_method, http_uri, http_headers={}, \
                               http_connection=None, http_body=''):
    if not http_connection:
      http_connection = self.http_connection
    if not self.oauth_consumer and http_headers.get('Authorization'):
      del http_headers['Authorization']
    http_headers.update({
      'Content-Length': len(http_body)
    })
    if http_body:
      http_headers.update({
        'Content-Type': 'application/json'
      })
    if self.oauth_consumer and self.oauth_access_token:
      # Build OAuth request and add OAuth header if we've got an access token
      oauth_request = self.build_oauth_request(http_method, http_uri)
      http_headers.update(oauth_request.to_header())
    try:
      try:
        http_connection.request(
          http_method, http_uri,
          headers=http_headers,
          body=http_body
        )
        response = http_connection.getresponse()
      except (httplib.BadStatusLine, httplib.CannotSendRequest):
        if http_connection and http_connection == self.http_connection:
          # Reset the connection
          http_connection.close()
          http_connection = None
          self._http_connection = None
          http_connection = self.http_connection
          # Retry once
          http_connection.request(
            http_method, http_uri,
            headers=http_headers,
            body=http_body
          )
          response = http_connection.getresponse()
    except Exception, e:
      if e.__class__.__name__ == 'ApplicationError' or \
          e.__class__.__name__ == 'DownloadError':
        if "5" in e.message:
          message = "Request timed out"
        else:
          message = "Request failed"
      else:
        message = str(e)
      json = None
      # If the raw JSON of the error is available, we don't want to lose it.
      if hasattr(e, '_json'):
        json = e._json
      raise RetrieveError(
        uri=http_uri,
        message=message,
        json=json
      )
    return response

  # People APIs

  def person(self, user_id='@me'):
    if isinstance(user_id, Person):
      # You'd think we could just return directly here, but sometimes a
      # Person object is incomplete, in which case this operation would
      # 'upgrade' to the full Person object.
      user_id = user_id.id
    if self.oauth_access_token:
      api_endpoint = API_PREFIX + ("/people/%s/@self" % user_id)
      api_endpoint += "?alt=json"
      return Result(
        self, 'GET', api_endpoint, result_type=Person, singular=True
      )
    else:
      raise ValueError("This client doesn't have an authenticated user.")

  def followers(self, user_id='@me'):
    if isinstance(user_id, Person):
      user_id = user_id.id
    api_endpoint = API_PREFIX + ("/people/%s/@groups/@followers" % user_id)
    api_endpoint += "?alt=json"
    return Result(self, 'GET', api_endpoint, result_type=Person)

  def following(self, user_id='@me'):
    if isinstance(user_id, Person):
      user_id = user_id.id
    api_endpoint = API_PREFIX + ("/people/%s/@groups/@following" % user_id)
    api_endpoint += "?alt=json"
    return Result(self, 'GET', api_endpoint, result_type=Person)

  def follow(self, user_id):
    if isinstance(user_id, Person):
      user_id = user_id.id
    if self.oauth_access_token:
      api_endpoint = API_PREFIX + (
        "/people/@me/@groups/@following/%s" % user_id
      )
      api_endpoint += "?alt=json"
      return Result(self, 'PUT', api_endpoint, result_type=None).data
    else:
      raise ValueError("This client doesn't have an authenticated user.")

  def unfollow(self, user_id):
    if isinstance(user_id, Person):
      user_id = user_id.id
    if self.oauth_access_token:
      api_endpoint = API_PREFIX + (
        "/people/@me/@groups/@following/%s" % user_id
      )
      api_endpoint += "?alt=json"
      return Result(self, 'DELETE', api_endpoint, result_type=None).data
    else:
      raise ValueError("This client doesn't have an authenticated user.")

  # Post APIs

  def search(self, query=None, latitude=None, longitude=None, radius=None):
    api_endpoint = API_PREFIX + "/activities/search?alt=json"
    if query:
      api_endpoint += "&q=" + urllib.quote_plus(query)
    if (latitude is not None) and (longitude is not None):
      api_endpoint += "&lat=" + urllib.quote(latitude)
      api_endpoint += "&lon=" + urllib.quote(longitude)
    if radius is not None:
      api_endpoint += "&radius=" + urllib.quote(str(radius))
    return Result(self, 'GET', api_endpoint, result_type=Post)

  def posts(self, type_id='@self', user_id='@me', max_results=20):
    if isinstance(user_id, Person):
      user_id = user_id.id
    api_endpoint = API_PREFIX + "/activities/" + str(user_id) + "/" + type_id
    api_endpoint += "?alt=json"
    if max_results:
      api_endpoint += "&max-results=" + str(max_results)
    return Result(self, 'GET', api_endpoint, result_type=Post)

  def post(self, post_id, actor_id='0'):
    if isinstance(actor_id, Person):
      actor_id = actor_id.id
    if isinstance(post_id, Post):
      post_id = post_id.id
    api_endpoint = API_PREFIX + "/activities/" + str(actor_id) + \
      "/@self/" + post_id
    api_endpoint += "?alt=json"
    return Result(self, 'GET', api_endpoint, result_type=Post, singular=True)

  def create_post(self, post):
    api_endpoint = API_PREFIX + "/activities/@me/@self"
    api_endpoint += "?alt=json"
    json_string = simplejson.dumps({'data': post._json_output})
    return Result(
      self, 'POST', api_endpoint, http_body=json_string, result_type=None
    ).data

  def update_post(self, post):
    if not post.id:
      raise ValueError('Post must have a valid id to update.')
    api_endpoint = API_PREFIX + "/activities/@me/@self/" + post.id
    api_endpoint += "?alt=json"
    json_string = simplejson.dumps({'data': post._json_output})
    return Result(
      self, 'PUT', api_endpoint, http_body=json_string, result_type=None
    ).data

  def delete_post(self, post):
    if not post.id:
      raise ValueError('Post must have a valid id to delete.')
    api_endpoint = API_PREFIX + "/activities/@me/@self/" + post.id
    api_endpoint += "?alt=json"
    return Result(self, 'DELETE', api_endpoint, result_type=None).data

  def comments(self, post_id, actor_id='0', max_results=20):
    if isinstance(actor_id, Person):
      actor_id = actor_id.id
    if isinstance(post_id, Post):
      post_id = post_id.id
    api_endpoint = API_PREFIX + "/activities/" + actor_id + \
      "/@self/" + post_id + "/@comments"
    api_endpoint += "?alt=json"
    if max_results:
      api_endpoint += "&max-results=" + str(max_results)
    return Result(self, 'GET', api_endpoint, result_type=Comment)

  def create_comment(self, comment):
    api_endpoint = API_PREFIX + ("/activities/%s/@self/%s/@comments" % (
      comment.post(client=self).actor.id,
      comment.post(client=self).id
    ))
    api_endpoint += "?alt=json"
    json_string = simplejson.dumps({'data': comment._json_output})
    return Result(
      self, 'POST', api_endpoint, http_body=json_string, result_type=None
    ).data

  def update_comment(self, comment):
    if not comment.id:
      raise ValueError('Comment must have a valid id to update.')
    api_endpoint = API_PREFIX + ("/activities/%s/@self/%s/@comments/%s" % (
      comment.actor.id,
      comment.post(client=self).id,
      comment.id
    ))
    api_endpoint += "?alt=json"
    json_string = simplejson.dumps({'data': comment._json_output})
    return Result(
      self, 'PUT', api_endpoint, http_body=json_string, result_type=None
    ).data

  def delete_comment(self, comment):
    if not comment.id:
      raise ValueError('Comment must have a valid id to update.')
    api_endpoint = API_PREFIX + ("/activities/%s/@self/%s/@comments/%s" % (
      comment.actor.id,
      comment.post(client=self).id,
      comment.id
    ))
    api_endpoint += "?alt=json"
    return Result(self, 'DELETE', api_endpoint, result_type=None).data

  def likers(self, post_id, actor_id='0', max_results=20):
    if isinstance(actor_id, Person):
      actor_id = actor_id.id
    if isinstance(post_id, Post):
      post_id = post_id.id
    api_endpoint = API_PREFIX + "/activities/" + actor_id + \
      "/@self/" + post_id + "/@likers"
    api_endpoint += "?alt=json"
    if max_results:
      api_endpoint += "&max-results=" + str(max_results)
    return Result(self, 'GET', api_endpoint, result_type=Person)

  # Likes
  # def liked_posts(self, user_id='@me'):
  #   """Returns a collection of posts that a user has liked."""
  #   return self.posts(type_id='@liked', user_id=user_id)

  def like_post(self, post_id):
    """
    Likes a post.
    """
    if isinstance(post_id, Post):
      post_id = post_id.id
    api_endpoint = API_PREFIX + "/activities/@me/@liked/" + post_id
    api_endpoint += "?alt=json"
    return Result(
      self, 'PUT', api_endpoint, result_type=None, singular=True
    ).data

  def unlike_post(self, post_id):
    """
    Unlikes a post.
    """
    if isinstance(post_id, Post):
      post_id = post_id.id
    api_endpoint = API_PREFIX + "/activities/@me/@liked/" + post_id
    api_endpoint += "?alt=json"
    return Result(
      self, 'DELETE', api_endpoint, result_type=None, singular=True
    ).data

  # Mutes
  # def muted_posts(self):
  #   """Returns a collection of posts that the current user has muted."""
  #   return self.posts(type_id='@muted', user_id='@me')

  def mute_post(self, post_id):
    """
    Mutes a post.
    """
    if isinstance(post_id, Post):
      post_id = post_id.id
    api_endpoint = API_PREFIX + "/activities/@me/@muted/" + post_id
    api_endpoint += "?alt=json"
    return Result(
      self, 'PUT', api_endpoint, result_type=None, singular=True
    ).data

  def unmute_post(self, post_id):
    """
    Unmutes a post.
    """
    if isinstance(post_id, Post):
      post_id = post_id.id
    api_endpoint = API_PREFIX + "/activities/@me/@muted/" + post_id
    api_endpoint += "?alt=json"
    return Result(
      self, 'DELETE', api_endpoint, result_type=None, singular=True
    ).data

  # OAuth debugging

  def oauth_token_info(self):
    """
    Returns information about the client's current access token.

    Allows a developer to verify that their token is valid.
    """
    api_endpoint = "https://www.google.com/accounts/AuthSubTokenInfo"
    if not self.oauth_access_token:
      raise ValueError("Client is missing access token.")
    response = self.fetch_api_response(
      'GET',
      api_endpoint,
      http_connection=self.oauth_http_connection
    )
    return response.read()

class Post:
  def __init__(self, json=None, client=None,
      content=None, uri=None, verb=None, actor=None,
      geocode=None, place_id=None,
      attachments=None):
    self.client = client
    self.json = json
    self.id = None
    self.object = None
    self.type=None
    self.place_name=None
    self.visibility=None
    
    # Construct the post piece-wise.
    self.content = content
    self.uri = uri
    self.verb = verb
    self.actor = actor
    self.geocode = geocode
    self.place_id = place_id
    self.attachments = attachments
    
    self._likers = None
    self._comments = None
    
    if self.json:
      # Parse the incoming JSON
      # Follow Postel's law
      try:
        json = _prune_json_envelope(json)
        self.id = json['id']
        if isinstance(json.get('content'), dict):
          self.content = json['content']['value']
        elif json.get('content'):
          self.content = json['content']
        elif json.get('object') and json['object'].get('content'):
          self.content = json['object']['content']
        if isinstance(json['title'], dict):
          self.title = json['title']['value']
        else:
          self.title = json['title']
        if json.get('object'):
          self.object = json['object']
        self.link = json['links']['alternate'][0]
        self.uri = self.link['href']
        if isinstance(json.get('verb'), list):
          self.verb = json['verb'][0]
        elif json.get('verb'):
          self.verb = json['verb']
        if isinstance(json.get('type'), list):
          self.type = json['type'][0]
        elif json.get('type'):
          self.type = json['type']
        elif self.object and self.object.get('type'):
          self.type = self.object['type']
        if json.get('author'):
          self.actor = Person(json['author'], client=self.client)
        elif json.get('actor'):
          self.actor = Person(json['actor'], client=self.client)
        if self.object and self.object.get('attachments'):
          self.attachments = [
            Attachment(attachment_json, client=self.client)
            for attachment_json
            in self.object['attachments']
          ]
        else:
          self.attachments = []
        if json.get('geocode'):
          self.geocode = _parse_geocode(json['geocode'])
        if json.get('placeName'):
          self.place_name = json['placeName']
        if json.get('visibility'):
          self.visibility = json['visibility']
          if isinstance(self.visibility, dict) and \
              self.visibility.get('entries'):
            self.visibility = self.visibility.get('entries')
        # TODO: handle timestamps
      except KeyError, e:
        raise JSONParseError(
          json=json,
          exception=e
        )

  def __repr__(self):
    if not self.public:
      return (u'<Post[%s] (private)>' % self.id).encode(
        'ASCII', 'ignore'
      )
    else:
      return (u'<Post[%s]>' % self.id).encode(
        'ASCII', 'ignore'
      )
  
  @property
  def public(self):
    if self.visibility:
      public_visibilities = [entry for entry in self.visibility if entry.get('id') == 'tag:google.com,2010:buzz-group:@me:@public']
      return not not public_visibilities
    else:
      # If there's no visibility attribute it's public
      return True
  
  @property
  def _json_output(self):
    output = {
      'object': {}
    }
    if self.id:
      output['id'] = self.id
    if self.uri:
      output['links'] = {
        u'alternate': [{u'href': self.uri, u'type': u'text/html'}]
      }
      output['object']['links'] = {
        u'alternate': [{u'href': self.uri, u'type': u'text/html'}]
      }
    if self.content:
      output['object']['content'] = self.content
    if self.type:
      output['object']['type'] = self.type
    else:
      output['object']['type'] = 'note'
    if self.verb:
      output['verb'] = self.verb
    if self.geocode:
      output['geocode'] = '%s %s' % (
        str(self.geocode[0]), str(self.geocode[1])
      )
    if self.place_id:
      output['placeId'] = self.place_id
    if self.attachments:
      output['object']['attachments'] = [
        attachment._json_output for attachment in self.attachments
      ]
    return output

  def comments(self, client=None):
    """Syntactic sugar for `client.comments(post)`."""
    if not client:
      client = self.client
    return self.client.comments(post_id=self.id, actor_id=self.actor.id)

  def likers(self, client=None):
    """Syntactic sugar for `client.likers(post)`."""
    if not client:
      client = self.client
    return self.client.likers(post_id=self.id, actor_id=self.actor.id)

  def like(self, client=None):
    """Syntactic sugar for `client.like_post(post)`."""
    if not client:
      client = self.client
    return client.like_post(post_id=self.id)

  def unlike(self, client=None):
    """Syntactic sugar for `client.unlike_post(post)`."""
    if not client:
      client = self.client
    return client.unlike_post(post_id=self.id)

  def mute(self, client=None):
    """Syntactic sugar for `client.mute_post(post)`."""
    if not client:
      client = self.client
    return client.mute_post(post_id=self.id)

  def unmute(self, client=None):
    """Syntactic sugar for `client.unmute_post(post)`."""
    if not client:
      client = self.client
    return client.unmute_post(post_id=self.id)

class Comment:
  def __init__(self, json=None, client=None,
      post=None, post_id=None, content=None):
    self.client = client
    self.json = json
    self.id = None
    self.content = content
    self.actor = None
    self._post = post
    self._post_id = post_id
    if json:
      # Follow Postel's law
      try:
        json = _prune_json_envelope(json)
        self.id = json['id']
        if isinstance(json.get('content'), dict):
          self.content = json['content']['value']
        elif json.get('content'):
          self.content = json['content']
        elif json.get('object') and json['object'].get('content'):
          self.content = json['object']['content']
        if json.get('author'):
          self.actor = Person(json['author'], client=self.client)
        elif json.get('actor'):
          self.actor = Person(json['actor'], client=self.client)
        if json.get('links') and json['links'].get('inReplyTo'):
          self._post_id = json['links']['inReplyTo'][0]['ref']
        # TODO: handle timestamps
      except KeyError, e:
        raise JSONParseError(
          json=json,
          exception=e
        )

  def __repr__(self):
    return (u'<Comment[%s]>' % self.id).encode(
      'ASCII', 'ignore'
    )

  @property
  def _json_output(self):
    output = {}
    if self.id:
      output['id'] = self.id
    if self.content:
      output['content'] = self.content
    return output

  def post(self, client=None):
    """Syntactic sugar for `client.post(post)`."""
    if not self._post:
      if not self._post_id:
        raise ValueError('Could not determine comment\'s parent post.')
      if not client:
        client = self.client
      if self.actor:
        self._post = \
          client.post(post_id=self._post_id, actor_id=self.actor.id).data
      else:
        self._post = \
          client.post(post_id=self._post_id).data
    return self._post

class Attachment:
  def __init__(self, json=None, client=None,
      type=None, title=None, content=None, uri=None,
      preview=None, enclosure=None):
    self.client = client
    self.json = json
    self.type = type
    self.title = title
    self.content = content
    self.uri = uri
    self.link = None
    self.preview = preview
    self.enclosure = enclosure
    if json:
      try:
        json = _prune_json_envelope(json)
        if isinstance(json.get('content'), dict):
          self.content = json['content']['value']
        elif json.get('content'):
          self.content = json['content']
        if json.get('title'):
          if isinstance(json['title'], dict):
            self.title = json['title']['value']
          else:
            self.title = json['title']
        else:
          self.title = None
        links = json.get('links')
        if links and links.get('alternate'):
          self.link = json['links']['alternate'][0]
          self.uri = self.link['href']
        if links and links.get('preview'):
          self.preview = json['links']['preview'][0]
        self.type = json['type']
      except KeyError, e:
        raise JSONParseError(
          json=json,
          exception=e
        )

  def __repr__(self):
    return (u'<Attachment[%s]>' % self.uri).encode(
      'ASCII', 'ignore'
    )

  @property
  def _json_output(self):
    output = {}
    if self.type:
      output['type'] = self.type
    if self.title:
      output['title'] = self.title
    if self.content:
      output['content'] = self.content
    if self.uri:
      output['links'] = {
        u'alternate': [{u'href': self.uri, u'type': u'text/html'}]
      }
    if self.preview:
      output['links'] = {
        u'preview': [{u'href': self.preview}]
      }
    if self.enclosure:
      output['links'] = {
        u'enclosure': [{u'href': self.enclosure}]
      }
    return output

class Person:
  def __init__(self, json, client=None):
    self.client = client
    self.json = json
    self.profile_name = None
    # Follow Postel's law
    try:
      json = _prune_json_envelope(json)
      self.uri = \
        json.get('uri') or json.get('profileUrl')
      if json.get('id'):
        self.id = json.get('id')
      else:
        self.id = re.search('/([^/]*?)$', self.uri).group(1)
      self.name = \
        json.get('name') or json.get('displayName')
      self.photo = \
        json.get('photoUrl') or json.get('thumbnailUrl')
      if self.photo and self.photo.startswith('/photos/public/'):
        self.photo = 'http://www.google.com/s2' + self.photo
      if json.get('urls'):
        self.uris = json.get('urls')
      if json.get('photos'):
        self.photos = json.get('photos')
      if not re.search('^\\d+$', re.search('/([^/]*?)$', self.uri).group(1)):
        self.profile_name = re.search('/([^/]*?)$', self.uri).group(1)
    except KeyError, e:
      raise JSONParseError(
        json=json,
        exception=e
      )

  def __repr__(self):
    return (u'<Person[%s, %s]>' % (self.name, self.id)).encode(
      'ASCII', 'ignore'
    )

  @property
  def _json_output(self):
    output = {}
    if self.id:
      output['id'] = self.id
    if self.name:
      output['name'] = self.name
    if self.uri:
      output['profileUrl'] = self.uri
    if self.photo:
      output['thumbnailUrl'] = self.photo
    return output
                
  def follow(self, client=None):
    """Syntactic sugar for `client.follow(person)`."""
    if not client:
      client = self.client
    return client.follow(user_id=self.id)

  def unfollow(self, client=None):
    """Syntactic sugar for `client.unfollow(person)`."""
    if not client:
      client = self.client
    return client.unfollow(user_id=self.id)

  def posts(self, client=None):
    """Syntactic sugar for `client.posts(person)`."""
    if not client:
      client = self.client
    return client.posts(user_id=self.id)

class Result:
  def __init__(self, client, http_method, http_uri, http_headers={}, \
      http_body='', result_type=Post, singular=False):
    self.client = client
    self.result_type = result_type
    self.singular = singular

    # The HTTP response for the current page
    self._response = None
    # The HTTP response body for the current page
    self._body = None
    # The raw JSON data for the current page
    self._json = None
    # The parsed data for the current page
    self._data = None
    # The URI of the next page of results
    self._next_uri = None

    self._http_method = http_method
    self._http_uri = http_uri
    self._http_headers = http_headers
    self._http_body = http_body

  def __iter__(self):
    return ResultIterator(self)

  @property
  def data(self):
    if not self._data:
      if not self._response:
        self.reload()
      if not (self._response.status >= 200 and self._response.status < 300):
        # Response was not a 2xx class status
        self._parse_error(self._json)
      if self.result_type == Post and self.singular:
        self._data = self._parse_post(self._json)
      elif self.result_type == Post and not self.singular:
        self._data = self._parse_posts(self._json)
      elif self.result_type == Comment and self.singular:
        self._data = self._parse_comment(self._json)
      elif self.result_type == Comment and not self.singular:
        self._data = self._parse_comments(self._json)
      elif self.result_type == Person and self.singular:
        self._data = self._parse_person(self._json)
      elif self.result_type == Person and not self.singular:
        self._data = self._parse_people(self._json)
    return self._data

  def reload(self):
    self._data = None
    self._response = self.client.fetch_api_response(
      http_method=self._http_method,
      http_uri=self._http_uri,
      http_headers=self._http_headers,
      http_body=self._http_body
    )
    self._body = self._response.read()
    try:
      if self._body == '':
        self._json = None
      else:
        self._json = simplejson.loads(self._body)
    except Exception, e:
      raise JSONParseError(
        json=(self._json or self._body),
        uri=self._http_uri,
        exception=e
      )

  def load_next(self):
    if self.next_uri:
      self._http_uri = self.next_uri
      # Reset all of these
      self._next_uri = None
      self._response = None
      self._body = None
      self._json = None
      self._data = None
    else:
      raise ValueError('Cannot load next page, next page not present.')

  @property
  def next_uri(self):
    if not self._next_uri:
      if self.singular:
        return None
      else:
        if not self._json:
          self.reload()
        semi_pruned_json = self._json.get('data') or self._json
        links = semi_pruned_json.get('links')
        if not links:
          return None
        next_link = links.get('next')
        if not next_link:
          return None
        self._next_uri = next_link[0].get('href')
        if not self._next_uri:
          return None
    return self._next_uri

  def _parse_post(self, json):
    """Helper method for converting a post JSON structure."""
    try:
      if json.get('error'):
        self.parse_error(json)
      json = _prune_json_envelope(json)
      if isinstance(json, list) and len(json) == 1:
        json = json[0]
      return Post(json, client=self.client)
    except KeyError, e:
      raise JSONParseError(
        uri=self._http_uri,
        json=json,
        exception=e
      )

  def _parse_posts(self, json):
    """Helper method for converting a set of post JSON structures."""
    try:
      if json.get('error'):
        self.parse_error(json)
      json = _prune_json_envelope(json)
      if isinstance(json, list):
        return [
          Post(post_json, client=self.client) for post_json in json
        ]
      else:
        # The entire key is omitted when there are no results
        return []
    except KeyError, e:
      raise JSONParseError(
        uri=self._http_uri,
        json=json,
        exception=e
      )

    def _parse_comment(self, json):
      """Helper method for converting a comment JSON structure."""
      try:
        if json.get('error'):
          self.parse_error(json)
        json = _prune_json_envelope(json)
        if isinstance(json, list) and len(json) == 1:
          json = json[0]
        return Comment(json, client=self.client)
      except KeyError, e:
        raise JSONParseError(
          uri=self._http_uri,
          json=json,
          exception=e
        )

  def _parse_comments(self, json):
    """Helper method for converting a set of comment JSON structures."""
    try:
      if json.get('error'):
        self.parse_error(json)
      json = _prune_json_envelope(json)
      if isinstance(json, list):
        return [
          Comment(comment_json, client=self.client) for comment_json in json
        ]
      else:
        # The entire key is omitted when there are no results
        return []
    except KeyError, e:
      raise JSONParseError(
        uri=self._http_uri,
        json=json,
        exception=e
      )

  def _parse_person(self, json):
    """Helper method for converting a person JSON structure."""
    try:
      if json.get('error'):
        self.parse_error(json)
      json = _prune_json_envelope(json)
      if isinstance(json, list) and len(json) == 1:
        json = json[0]
      return Person(json, client=self.client)
    except KeyError, e:
      raise JSONParseError(
        uri=self._http_uri,
        json=json,
        exception=e
      )

  def _parse_people(self, json):
    """Helper method for converting a set of person JSON structures."""
    try:
      if json.get('error'):
        self.parse_error(json)
      json = _prune_json_envelope(json)
      if isinstance(json, list):
        return [
          Person(person_json, client=self.client) for person_json in json
        ]
      else:
        # The entire key is omitted when there are no results
        return []
    except KeyError, e:
      raise JSONParseError(
        uri=self._http_uri,
        json=json,
        exception=e
      )

  def _parse_error(self, json):
    """Helper method for converting an error response to an exception."""
    if json:
      raise RetrieveError(
        uri=self._http_uri,
        message=json['error'].get('message'),
        json=json
      )
    else:
      raise RetrieveError(
        uri=self._http_uri,
        message='Unknown error'
      )
    

class ResultIterator:
  def __init__(self, result):
    self.result = result
    self.cursor = 0
    self.start_index = 0

  def __iter__(self):
    return self

  @property
  def local_index(self):
    return self.cursor - self.start_index

  def next(self):
    if self.local_index >= len(self.result.data):
      if self.result.next_uri:
        self.start_index += len(self.result.data)
        self.result.load_next()
      else:
        raise StopIteration('No more results.')
    # The local_index is in range of the current page
    value = self.result.data[self.local_index]
    self.cursor += 1
    return value
