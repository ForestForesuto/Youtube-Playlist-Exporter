"""Google Credential Manager to make sure we have the user token"""

import json
import os

from dotenv import load_dotenv
from google.auth.external_account_authorized_user import Credentials as AuthCredentials
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials as NormCredentials
from google_auth_oauthlib.flow import InstalledAppFlow

load_dotenv(".env")
CLIENT_SECRET_FILE = os.environ["CLIENT_SECRET_PATH_FILE"]

def _get_token() -> NormCredentials | AuthCredentials:
    """Redirects the user to a browser to get authenticated data.

    User gets promted to a browser log in page of google to get
    permission to use their account youtube data. When user is
    fully authenticated, we save their token information in a
    .json file locally.

    Returns:
        NormCredentials | AuthCredentials: The token information
            of the user.
    """
    flow = InstalledAppFlow.from_client_secrets_file(
        CLIENT_SECRET_FILE,
        scopes=[
            'https://www.googleapis.com/auth/youtube.readonly',
        ],
    )

    credentials = flow.run_local_server(port=0)

    with open('token.json', 'w') as file:
        file.write(credentials.to_json())

    return credentials

def _refresh_token(credentials: NormCredentials | AuthCredentials) -> None:
    """Refreshes the user's token credentials.

    Sends a refresh request to google. When the refreshed token is
    sucessfully acquired, we save it to a new/existing .json file.

    Args:
        credentials (NormCredentials | AuthCredentials): The token
            information of the user.
    """
    credentials.refresh(Request())
    with open('token.json', 'w') as file:
        file.write(credentials.to_json())
    return None

def get_credentials() -> NormCredentials | AuthCredentials:
    """Gets or Fetches the user's token credentials.

    If a cache of user's token is found locally, it will be
    used. If the cached token is expired, it will request
    a new token to be made and return it. While if no cache
    is found, it will promt the user to get authenticated
    and return the data after it is done.

    Returns:
        NormCredentials | AuthCredentials: The token
            information of the user.
    """
    credentials: NormCredentials | AuthCredentials | None = None

    if os.path.exists('token.json'):
        with open('token.json') as token_file:
            credentials = NormCredentials.from_authorized_user_info(json.load(token_file))

    if not credentials or not credentials.valid:
        if credentials and credentials.expired and credentials.refresh_token:
            _refresh_token(credentials)
        else:
            credentials = _get_token()

    return credentials
