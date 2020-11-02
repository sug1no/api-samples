#!/usr/bin/python

import argparse
import http.client
import httplib2
import os
import random
import time

import google.oauth2.credentials
import google_auth_oauthlib.flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaFileUpload
from google_auth_oauthlib.flow import InstalledAppFlow

# pip install pyjwt
# pip install cryptography
# pip install jwt
from jwt.algorithms import RSAAlgorithm
import jwt

import requests
import json

from logging import getLogger
logger = getLogger(__name__)

# Explicitly tell the underlying HTTP transport library not to retry, since
# we are handling retry logic ourselves.
httplib2.RETRIES = 1

# Maximum number of times to retry before giving up.
MAX_RETRIES = 10

# Always retry when these exceptions are raised.
RETRIABLE_EXCEPTIONS = (httplib2.HttpLib2Error, IOError, http.client.NotConnected,
  http.client.IncompleteRead, http.client.ImproperConnectionState,
  http.client.CannotSendRequest, http.client.CannotSendHeader,
  http.client.ResponseNotReady, http.client.BadStatusLine)

# Always retry when an apiclient.errors.HttpError with one of these status
# codes is raised.
RETRIABLE_STATUS_CODES = [500, 502, 503, 504]

# The CLIENT_SECRETS_FILE variable specifies the name of a file that contains
# the OAuth 2.0 information for this application, including its client_id and
# client_secret. You can acquire an OAuth 2.0 client ID and client secret from
# the {{ Google Cloud Console }} at
# {{ https://cloud.google.com/console }}.
# Please ensure that you have enabled the YouTube Data API for your project.
# For more information about using OAuth2 to access the YouTube Data API, see:
#   https://developers.google.com/youtube/v3/guides/authentication
# For more information about the client_secrets.json file format, see:
#   https://developers.google.com/api-client-library/python/guide/aaa_client_secrets
# specify clientid and secret to verify and use to inboke youtube API (ex.. for webapp).
CLIENT_SECRETS_FILE = 'client_secret_webapp.json'

# This OAuth 2.0 access scope allows an application to upload files to the
# authenticated user's YouTube channel, but doesn't allow other types of access.
SCOPES = ['https://www.googleapis.com/auth/youtube.upload']
API_SERVICE_NAME = 'youtube'
API_VERSION = 'v3'

VALID_PRIVACY_STATUSES = ('public', 'private', 'unlisted')


# Authorize the request and store authorization credentials.
def get_authenticated_service():
  flow = InstalledAppFlow.from_client_secrets_file(CLIENT_SECRETS_FILE, SCOPES)

  clientId = flow.client_config['client_id']
  clienSecret = flow.client_config['client_secret']
  idToken = input('Enter the authorized id_token for client_id=%s: ' % clientId)
  settings_SOCIAL_AUTH_GOOGLE_CLIENT_ID = clientId;


  # https://github.com/FlowMachinesStudio/fmpro_server/commit/874efc7f67c71cb9c9f437b81db85158b6192995

  JWKS_URI = 'https://www.googleapis.com/oauth2/v3/certs'
  # GOOGLE_ISSUER = 'https://accounts.google.com'
  GOOGLE_ISSUER = 'accounts.google.com'

  try:
    id_token = idToken
    unsafeclaims = jwt.decode(id_token, verify=False)
    header = jwt.get_unverified_header(id_token)
    # Get Public Key
    res = requests.get(JWKS_URI)
    jwk_set = res.json()
    jwk = next(filter(lambda k: k['kid'] == header['kid'], jwk_set['keys']))
    public_key = RSAAlgorithm.from_jwk(json.dumps(jwk))
    # Verify
    claims = jwt.decode(id_token,
                        public_key,
                        issuer=unsafeclaims['iss'],
                        audience=settings_SOCIAL_AUTH_GOOGLE_CLIENT_ID,
                        algorithms=["RS256"])
    logger.debug("JWT decode. claims: [{}]".format(claims))
  except Exception as e:
    logger.error("JWT decode False. [{}] [{}]".format(id_token, e))
    raise AuthenticationFailed("JWT decode False.")




  # credentials = flow.run_console()
  return build(API_SERVICE_NAME, API_VERSION, credentials = credentials)

def initialize_upload(youtube, options):
  tags = None
  if options.keywords:
    tags = options.keywords.split(',')

  body=dict(
    snippet=dict(
      title=options.title,
      description=options.description,
      tags=tags,
      categoryId=options.category
    ),
    status=dict(
      privacyStatus=options.privacyStatus
    )
  )

  # Call the API's videos.insert method to create and upload the video.
  insert_request = youtube.videos().insert(
    part=','.join(list(body.keys())),
    body=body,
    # The chunksize parameter specifies the size of each chunk of data, in
    # bytes, that will be uploaded at a time. Set a higher value for
    # reliable connections as fewer chunks lead to faster uploads. Set a lower
    # value for better recovery on less reliable connections.
    #
    # Setting 'chunksize' equal to -1 in the code below means that the entire
    # file will be uploaded in a single HTTP request. (If the upload fails,
    # it will still be retried where it left off.) This is usually a best
    # practice, but if you're using Python older than 2.6 or if you're
    # running on App Engine, you should set the chunksize to something like
    # 1024 * 1024 (1 megabyte).
    media_body=MediaFileUpload(options.file, chunksize=-1, resumable=True)
  )

  resumable_upload(insert_request)

# This method implements an exponential backoff strategy to resume a
# failed upload.
def resumable_upload(request):
  response = None
  error = None
  retry = 0
  while response is None:
    try:
      print('Uploading file...')
      status, response = request.next_chunk()
      if response is not None:
        if 'id' in response:
          print(('Video id "%s" was successfully uploaded.' % response['id']))
        else:
          exit('The upload failed with an unexpected response: %s' % response)
    except( HttpError, e):
      if e.resp.status in RETRIABLE_STATUS_CODES:
        error = 'A retriable HTTP error %d occurred:\n%s' % (e.resp.status,
                                                             e.content)
      else:
        raise
    except (RETRIABLE_EXCEPTIONS, e):
      error = 'A retriable error occurred: %s' % e

    if error is not None:
      print(error)
      retry += 1
      if retry > MAX_RETRIES:
        exit('No longer attempting to retry.')

      max_sleep = 2 ** retry
      sleep_seconds = random.random() * max_sleep
      print(('Sleeping %f seconds and then retrying...' % sleep_seconds))
      time.sleep(sleep_seconds)

if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  parser.add_argument('--file', required=True, help='Video file to upload')
  parser.add_argument('--title', help='Video title', default='Test Title')
  parser.add_argument('--description', help='Video description',
    default='Test Description')
  parser.add_argument('--category', default='22',
    help='Numeric video category. ' +
      'See https://developers.google.com/youtube/v3/docs/videoCategories/list')
  parser.add_argument('--keywords', help='Video keywords, comma separated',
    default='')
  parser.add_argument('--privacyStatus', choices=VALID_PRIVACY_STATUSES,
    default='private', help='Video privacy status.')
  args = parser.parse_args()

  youtube = get_authenticated_service()

  try:
    initialize_upload(youtube, args)
  except (HttpError, e):
    print(('An HTTP error %d occurred:\n%s' % (e.resp.status, e.content)))
