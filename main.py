from datetime import datetime, timedelta
from http import HTTPStatus
from json import dumps, loads, dump, load
from os import getenv
from tempfile import NamedTemporaryFile

from boto3 import client
from google.auth.transport.requests import AuthorizedSession
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow

SCOPES = [
    "https://www.googleapis.com/auth/photoslibrary",
    "https://www.googleapis.com/auth/photoslibrary.sharing",
]

SECRETS_CLIENT = client(
    "secretsmanager",
    region_name="eu-west-1",
    aws_access_key_id=getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=getenv("AWS_SECRET_ACCESS_KEY"),
)

SECRET_ID = "dji-media-uploader-auth-json"

CLIENT_ID_JSON = {
    "installed": {
        "client_id": None,
        "client_secret": None,
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://www.googleapis.com/oauth2/v3/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "redirect_uris": ["urn:ietf:wg:oauth:2.0:oob", "http://localhost"],
    }
}


def get_auth_json():
    """Retrieves the Auth JSON from AWS Secrets Manager

    Returns:
        dict: the Auth JSON
    """

    auth_json = loads(
        SECRETS_CLIENT.get_secret_value(
            SecretId=SECRET_ID,
        ).get("SecretString", "{}")
    )

    return auth_json


def authorize_application():
    """Opens the user's browser to authorize the media uploader application
    for their Google account

    Returns:
        Credentials: The OAuth 2.0 credentials for the user
    """

    auth_json = get_auth_json()

    tmp_client_id_json = NamedTemporaryFile()

    with open(tmp_client_id_json.name, "w") as fout:
        CLIENT_ID_JSON["installed"]["client_id"] = auth_json.get("client_id")
        CLIENT_ID_JSON["installed"]["client_secret"] = auth_json.get("client_secret")

        dump(CLIENT_ID_JSON, fout)

    flow = InstalledAppFlow.from_client_secrets_file(
        tmp_client_id_json.name, scopes=SCOPES
    )

    credentials = flow.run_local_server(
        host="localhost",
        port=8080,
        authorization_prompt_message="",
        success_message="The auth flow is complete; you may close this window.",
        open_browser=True,
    )

    return credentials


def get_authorized_session():
    auth_json = get_auth_json()

    if not auth_json:
        raise ValueError("Auth JSON not retrieved from Secrets Manager")

    tmp_auth_file = NamedTemporaryFile()

    with open(tmp_auth_file.name, "w") as fout:
        dump(auth_json, fout)

    cred = Credentials.from_authorized_user_file(tmp_auth_file.name, SCOPES)

    if not cred:
        cred = authorize_application()

    session = AuthorizedSession(cred)

    res = SECRETS_CLIENT.update_secret(
        SecretId=SECRET_ID,
        SecretString=dumps(
            {
                "token": cred.token,
                "refresh_token": cred.refresh_token,
                "id_token": cred.id_token,
                "scopes": cred.scopes,
                "token_uri": cred.token_uri,
                "client_id": cred.client_id,
                "client_secret": cred.client_secret,
            }
        ),
    )

    if res.get("ResponseMetadata", {}).get("HTTPStatusCode", -1) != HTTPStatus.OK:
        raise ValueError("Unable to update Auth JSON secret")

    return session


def get_media_items(session):
    try:
        with open("media_items.json") as fin:
            old_media_items = load(fin)
    except FileNotFoundError:
        print("`media_items.json` not found - downloading all media items. This may take some time...")
        old_media_items = []

    most_recent_dttm = (
        datetime.strptime(
            max(
                item.get("mediaMetadata", {}).get("creationTime", -1)
                for item in old_media_items
            ),
            "%Y-%m-%dT%H:%M:%SZ",
        )
        if old_media_items
        else datetime(1970, 1, 8)
    )

    a_week_before = most_recent_dttm - timedelta(days=7)

    print(
        f"Newest media item was created at `{most_recent_dttm}`, downloading all items since `{a_week_before}` to be safe")

    filters = {
        "filters": {
            "dateFilter": {
                "ranges": [
                    {
                        "startDate": {
                            "year": a_week_before.year,
                            "month": a_week_before.month,
                            "day": a_week_before.day,
                        },
                        "endDate": {"year": 3000, "month": 1, "day": 1},
                    }
                ]
            }
        }
    }

    params = {
        "pageSize": "100",
    }

    res = session.post(
        "https://photoslibrary.googleapis.com/v1/mediaItems:search",
        params=params,
        json=filters,
    )
    new_media_items = res.json().get("mediaItems", [])

    while "nextPageToken" in res.json():
        params["pageToken"] = res.json()["nextPageToken"]
        res = session.post(
            "https://photoslibrary.googleapis.com/v1/mediaItems:search",
            params=params,
            json=filters,
        )
        new_media_items.extend(res.json().get("mediaItems", []))

    old_ids = [item.get("id") for item in old_media_items]

    # Remove old items re-downloaded due to the 7 day overlap
    new_media_items = [item for item in new_media_items if item.get("id") not in old_ids]

    print(f"{len(new_media_items)} new items downloaded")

    all_media_items = sorted(
        old_media_items + new_media_items,
        key=lambda item: item.get("mediaMetadata", {}).get("creationTime", "-1"),
        reverse=True
    )

    with open("media_items.json", "w") as fout:
        dump(all_media_items, fout)

    return all_media_items


def main():
    session = get_authorized_session()

    media_items = get_media_items(session)


if __name__ == "__main__":
    main()
