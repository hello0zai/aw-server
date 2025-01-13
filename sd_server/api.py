import functools
from itertools import groupby
import json
import logging
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
from socket import gethostname
import threading
import time

from sd_core import db_cache
from sd_core.cache import cache_user_credentials
from sd_core.cache import *
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Optional,
    Union,
)
from uuid import uuid4
from sd_core.util import decrypt_uuid, encrypt_uuid, load_key, is_internet_connected

import iso8601
from sd_core.dirs import get_data_dir
from sd_core.log import get_log_file_path
from sd_core.models import Event
from sd_query import query2
from sd_transform import heartbeat_merge
import keyring
import pytz

from .__about__ import __version__
from .exceptions import NotFound
import requests as req
from dateutil import parser
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry


logger = logging.getLogger(__name__)

if os.environ.get('SSLKEYLOGFILE'):
    os.environ.pop('SSLKEYLOGFILE', None)


def get_device_id() -> str:
    path = Path(get_data_dir("sd-server")) / "device_id"
    if path.exists():
        with open(path) as f:
            return f.read()
    else:
        uuid = str(uuid4())
        with open(path, "w") as f:
            f.write(uuid)
        return uuid

def create_retry_session(retries=3, backoff_factor=0.3):
    session = requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=[500, 502, 503, 504]
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('https://', adapter)
    session.mount('http://', adapter)
    return session

def check_bucket_exists(f):
    @functools.wraps(f)
    def g(self, bucket_id, *args, **kwargs):
        if bucket_id not in self.db.buckets():
            raise NotFound("NoSuchBucket", f"There's no bucket named {bucket_id}")
        return f(self, bucket_id, *args, **kwargs)

    return g

def always_raise_for_request_errors(f: Callable[..., req.Response]):
    @functools.wraps(f)
    def g(*args, **kwargs):
        r = f(*args, **kwargs)
        try:
            r.raise_for_status()
        except req.RequestException as e:
            _log_request_exception(e)
            raise e
        return r

    return g

def _log_request_exception(e: req.RequestException):
    r = e.response
    logger.warning(str(e))
    try:
        d = r.json()
        logger.warning(f"Error message received: {d}")
    except json.JSONDecodeError:
        pass


class ServerAPI:
    def __init__(self, db, testing: bool) -> None:
        """
        Initialize the Sundial instance. This is the method that must be called by the user to initialize the Sundial instance.

        :param db: Database instance to use for communication.
        :param testing: True if we are testing, False otherwise.
        :return: None
        """
        cache_key = "Sundial"
        cache_user_credentials("Sundial")
        self.db = db
        self.testing = testing
        self.last_event = {}  # Stores the last event for each bucket to optimize event updates.

        # Configure server address.
        protocol = 'https'
        host = 'ralvie.minervaiotdev.com'
        self.server_address = f"{protocol}://{host}"

        # Initialize the RalvieServerQueue for handling background sync tasks.
        try:
            self.ralvie_server_queue = RalvieServerQueue(self)
            logger.info("RalvieServerQueue initialized successfully.")
        except Exception as e:
            logger.error(f"Failed to initialize RalvieServerQueue: {e}")
            self.ralvie_server_queue = None

    def save_settings(self, code, value) -> None:
        """
         Save settings to the database. This is a low - level method for use by plugins that want to save settings to the database as part of their initialization and / or reinitialization.

         @param settings_id - ID of the settings to save.
         @param settings_dict - Dictionary of settings to save. Keys must match the names of the settings in the dictionary.

         @return True if successful False otherwise. Raises : py : exc : ` ~sqlalchemy. exc. IntegrityError ` if there is a problem
        """
        return self.db.save_settings(code=code,value=value)

    def get_settings(self, code) -> Dict[str, Any]:
        """
         Retrieve settings from the database. This is a low - level method to be used by plugins that want to retrieve settings from the database.

         @param settings_id - ID of the settings to retrieve.

         @return Dictionary of settings. Keys are the names of the settings
        """
        return self.db.retrieve_setting(code=code)

    def retrieve_all_settings(self):
        return self.db.retrieve_all_settings()

    def update_settings(self,code,value):
        return self.db.update_settings(code=code,value=value)

    def delete_settings(self,code):
        return self.db.delete_settings(code=code)

    def save_application_details(self, application_details):
        try:
            # Save application details to the database
            saved_details = self.db.save_application_details(application_details)
            return saved_details
        except Exception:
            # Handle the error
            return None
    def get_appication_details(self):
        return self.db.retrieve_application_details()

    def update_application_details(self, update_details):
        try:
            update_details=self.db.update_application_details(update_details)
            return update_details
        except Exception:
            return None

    def delete_application_details(self,application_id):
        try:
            delete_app=self.db.delete_application_details(application_id)
            return delete_app
        except Exception:
            return None

    def application_list(self):
        return self.db.retrieve_application_names()

    def _url(self, endpoint: str):
        """
         Generate URL for an API. This is used to generate the URL that will be used to access the API.

         @param endpoint - The endpoint to access. Must be prefixed with the server address e. g.

         @return The URL to access the API with the given endpoint
        """
        return f"{self.server_address}{endpoint}"

    @always_raise_for_request_errors
    def _get(self, endpoint: str, params: Optional[dict] = None) -> req.Response:
        """
         Make a GET request to Cerebrum and return the response. This is a helper for _get_url and _get_url_with_params

         @param endpoint - The endpoint to call e. g.
         @param params - A dictionary of key / value pairs to include in the request

         @return A : class : ` Response `
        """
        headers = {"Content-type": "application/json", "charset": "utf-8"}
        # Update the headers with the params.
        if params:
            headers.update(params)
        return req.get(self._url(endpoint), headers=headers)

    @always_raise_for_request_errors
    def _post(

        self,
        endpoint: str,
        data: Union[List[Any], Dict[str, Any]],
        params: Optional[dict] = None,
    ) -> req.Response:
        """
         Send a POST request to the API. This is a helper for : meth : ` _url ` to make it easier to use in conjunction with

         @param endpoint - The endpoint to send the request to.
         @param data - The data to send as the body of the request.
         @param params - A dictionary of headers to add to the request.

         @return The response from the request as a : class : ` req. Response `
        """
        headers = {"Content-type": "application/json", "charset": "utf-8"}
        # Update the headers with the params.
        if params:
            headers.update(params)
        return req.post(
            self._url(endpoint),
            data=bytes(json.dumps(data), "utf8"),
            headers=headers,
            params=params,
        )

    @always_raise_for_request_errors
    def _put(

        self,
        endpoint: str,
        data: Union[List[Any], Dict[str, Any]],
        params: Optional[dict] = None,
    ) -> req.Response:
        """
         Send a POST request to the API. This is a helper for : meth : ` _url ` to make it easier to use in conjunction with

         @param endpoint - The endpoint to send the request to.
         @param data - The data to send as the body of the request.
         @param params - A dictionary of headers to add to the request.

         @return The response from the request as a : class : ` req. Response `
        """
        headers = {"Content-type": "application/json", "charset": "utf-8"}
        # Update the headers with the params.
        if params:
            headers.update(params)
        return req.put(
            self._url(endpoint),
            data=bytes(json.dumps(data), "utf8"),
            headers=headers,
            params=params,
        )



    @always_raise_for_request_errors
    def _put_with_file(
        self,
        endpoint: str,
        file,
        params: Optional[dict] = None,
    ) -> req.Response:
        """
         Send a POST request to the API. This is a helper for : meth : ` _url ` to make it easier to use in conjunction with

         @param endpoint - The endpoint to send the request to.
         @param data - The data to send as the body of the request.
         @param params - A dictionary of headers to add to the request.

         @return The response from the request as a : class : ` req. Response `
        """
        headers = {}
        payload = {}

        # Update the headers with the params.
        if params:
            headers.update(params)
        files = {'file': (file.filename, file.stream, file.content_type)}
        return req.put(
            self._url(endpoint),
            headers=headers, data=payload, files=files,
        )

    @always_raise_for_request_errors
    def _delete(self, endpoint: str, data: Any = dict(),
        params: Optional[dict] = None) -> req.Response:
        """
         Send a DELETE request to Cobbler. This is a helper method for : meth : ` delete_and_recover `.

         @param endpoint - The endpoint to send the request to. E. g.
         @param data - The data to send as the body of the request.

         @return A : class : ` req. Response ` object
        """
        headers = {"Content-type": "application/json"}
        if params:
            headers.update(params)
        return req.delete(self._url(endpoint), data=json.dumps(data), headers=headers)


    def init_db(self) -> bool:
        """
         Initialize the database. This is called after the connection has been established and all tables have been loaded.


         @return True if successful False if not ( in which case the database is in an error state
        """
        return self.db.init_db()

    def create_user(self, user:Dict[str, Any]):
        """
         Create a user on behalf of the authenticated user. This is a POST request to the ` ` / web / user ` ` endpoint.

         @param user - A dictionary containing the information to create the user on behalf of.

         @return The response from the server that was received as part of the request
        """
        endpoint = f"/web/user"
        return self._post(endpoint , user)

    def authorize(self, user:Dict[str, Any]):
        """
         Authorize a user. This is a POST request to the ` / web / user / authorize ` endpoint.

         @param user - The user to authorize. See API docs for more information.

         @return The response from the server. If there was an error the response will contain the error
        """
        endpoint = f"/web/user/authorize"
        return self._post(endpoint , user)

    def refresh_token(self, payload:Dict[str, Any]):
        """
         Refresh token. This is a PUT request to the ` / web / user / authorize / refresh_token` endpoint.

         @param payload - The payload which contains refresh_token to create new access token. See API docs for more information.

         @return The response from the server. If there was an error the response will contain the error
        """
        endpoint = f"/web/user/authorize/refresh_token"
        return self._put(endpoint , payload)


    def update_user_profile(self, access_token, file):
        cache_key = "Sundial"
        cached_credentials = get_credentials(cache_key)
        user_id = cached_credentials.get("userId")
        if user_id:
            endpoint = f"/web/user/{user_id}/profile"
            response = self._put_with_file(endpoint, file, {"Authorization" : access_token})

        if response.status_code == 200:
            return {"code": json.loads(response.text)["code"], "message": json.loads(response.text)["message"],
                    "data": json.loads(response.text)["data"]}, 200
        return {"status": "error", "message": "Failed"}

    def create_company(self, user:Dict[str, Any], token):
        """
         Create a company for the user. This is a POST request to the ` / web / company ` endpoint.

         @param user - Dictionary containing the user's data. See example below.
         @param token - Authorization token to use for this request. See example below.

         @return A response from the server that contains the company ID
        """
        endpoint = f"/web/company"
        return self._post(endpoint , user, {"Authorization" : token})

    def sync_appdata_to_ralvie(self, data: Dict[str, Any],token) -> Any:
        """
        Sync application data to Ralvie.
        """
        endpoint = "/web/open/application"
        return self._post(endpoint, data,{"Authorization" : token})
        # return self._post(endpoint, data,{"Authorization" : token})

    def sync_events_to_ralvie(self):
        try:
            userId = load_key("userId")
            logger.info(f"User ID from load_key: {userId}")
            cache_key = "Sundial"
            cached_credentials = get_credentials(cache_key)
            companyId = cached_credentials.get('companyId')
            token = cached_credentials.get('token')

            if not userId or not token:
                logger.warning("User ID or token is missing; unable to sync.")
                return {"status": "missing_credentials"}

            data = self.get_non_sync_events()
            if data.get("status") == "NoEvents":
                return {"status": "NoEvents"}

            events = data.get("events", [])
            if events:
                payload = {"userId": userId, "companyId": companyId, "events": events}
                endpoint = "/web/event"
                response = self._post(endpoint, payload, {"Authorization": token})

                if response.status_code == 200:
                    response_data = json.loads(response.text)
                    if response_data.get("code") == 'RCI0000':
                        event_ids = [obj['event_id'] for obj in events]
                        self.db.update_server_sync_status(list_of_ids=event_ids, new_status=1)
                        self.db.save_settings("last_sync_time", datetime.now(timezone.utc).astimezone().isoformat())
                        logger.info(f"Successfully synced {len(events)} events.")
                        return {"status": "success"}
                    else:
                        logger.error(f"Unexpected response code: {response_data.get('code')}")
                        return {"status": "unexpected_response_code", "code": response_data.get("code")}
                else:
                    logger.error(f"Sync failed with status code: {response.status_code}")
                    return {"status": "sync_failed", "error": response.text}
            else:
                logger.info("No events to sync.")
                return {"status": "no_events"}
        except Exception as e:
            logger.error(f"Error during sync_events_to_ralvie: {e}")
            return {"status": "error_occurred", "message": str(e)}

    def get_user_credentials(self, userId, token):
        """
        Get credentials for a user. This is a wrapper around the get_credentials endpoint to provide access to the user's credentials.

        @param userId: User ID
        @param token: Authorization token
        """

        cache_key = "Sundial"
        endpoint = f"/web/user/{userId}/credentials"
        user_credentials = self._get(endpoint, {"Authorization": token})

        if user_credentials.status_code == 200 and json.loads(user_credentials.text)["code"] == 'RCI0000':
            credentials_data = json.loads(user_credentials.text)["data"]["credentials"]
            user_data = json.loads(user_credentials.text)["data"]["user"]

            # Clear the cache and keychain only for the relevant service key (SD_KEYS)
            clear_credentials("Sundial")
            delete_password("Sundial")

            # Extract and encrypt credentials
            db_key = credentials_data["dbKey"]
            data_encryption_key = credentials_data["dataEncryptionKey"]
            user_key = credentials_data["userKey"]
            email = user_data.get("email", None)
            phone = user_data.get("phone", None)
            companyId = user_data.get("companyId", None)
            companyName = user_data.get("companyName", None)
            firstName = user_data.get("firstName", None)
            key = user_key
            encrypted_db_key = encrypt_uuid(db_key, key)
            encrypted_data_encryption_key = encrypt_uuid(data_encryption_key, key)
            encrypted_user_key = encrypt_uuid(user_key, key)
            # Create the SD_KEYS dictionary
            SD_KEYS = {
                "user_key": user_key,
                "encrypted_db_key": encrypted_db_key,
                "encrypted_data_encryption_key": encrypted_data_encryption_key,
                "email": email,
                "phone": phone,
                "firstname": firstName,
                "userId": userId,
                "token": token,
                "companyId": companyId,
                "companyName": companyName,
                "Authenticated": True,
            }

            # Update the cache first
            store_credentials("Sundial", SD_KEYS)

            # Serialize the data and update the secure storage
            serialized_data = json.dumps(SD_KEYS)
            status = add_password("Sundial", serialized_data)
            print(status)
            # Retrieve the cached credentials to confirm they were updated
            cached_credentials = get_credentials("Sundial")
            if cached_credentials:
                key_decoded = cached_credentials.get("user_key")
                self.last_event = {}

        return user_credentials

    def get_user_by_id(self, token):
        """
        Get credentials for a user. This is a wrapper around the get_credentials endpoint to provide access to the user '

        @param userId
        @param token
        """

        cache_key = "Sundial"
        cached_credentials = get_credentials(cache_key)
        user_id = cached_credentials.get("userId")

        endpoint = f"/web/user/{user_id}"
        user = self._get(endpoint, {"Authorization": token})

        # This function is used to retrieve the user credentials.
        if user.status_code == 200:
            return json.loads(user.text)
        else:
            return None

    def delete_user_profile_photo(self, token):
        """
        Delete profile photo of a user.'

        @param userId
        @param token
        """

        cache_key = "Sundial"
        cached_credentials = get_credentials(cache_key)
        user_id = cached_credentials.get("userId")

        endpoint = f"/web/user/{user_id}/profile"
        user = self._delete(endpoint, {}, {"Authorization": token})

        return json.loads(user.text)

    def get_user_details(self):
        """
         Get details of user. This is used to populate the Sundial page in the admin.


         @return Dictionary that contains email phone firstname and lastname
        """
        cache_key = "Sundial"
        cached_credentials = get_credentials(cache_key)

        image = self.db.retrieve_setting("profilePic")
        response_data = {"email": cached_credentials.get("email"), "phone": cached_credentials.get("phone"),
                         "firstname": cached_credentials.get("firstname"),
                         "lastname": cached_credentials.get("lastname")}
        # Set the image s profile image
        if image:
            response_data['ProfileImage'] = image
        else:
            response_data['ProfileImage'] = ""
        # Return cached credentials if cached credentials are not None.
        if not cached_credentials is None:
            return response_data


    def get_info(self) -> Dict[str, Any]:
        """
         Get information about the server. This is a dictionary that can be sent to the server to update the configuration.


         @return A dictionary that can be sent to the server to update
        """
        """Get server info"""
        payload = {
            "hostname": gethostname(),
            "version": __version__,
            "testing": self.testing,
            "device_id": get_device_id(),
        }
        return payload

    def get_buckets(self) -> Dict[str, Dict]:
        """
         Get all buckets from the database and add last_updated field to each bucket


         @return Dictionary of all buckets in the database with keys :
        """
        """Get dict {bucket_name: Bucket} of all buckets"""
        logger.debug("Received get request for buckets")
        buckets = self.db.buckets()
        # Update the last_updated timestamp and duration of each bucket
        for b in buckets:
            # TODO: Move this code to sd-core?
            last_events = self.db[b].get(limit=1)
            # Update the last_updated timestamp and duration of last_event.
            if len(last_events) > 0:
                last_event = last_events[0]
                last_updated = last_event.timestamp + last_event.duration
                buckets[b]["last_updated"] = last_updated.isoformat()
        return buckets

    @check_bucket_exists
    def get_bucket_metadata(self, bucket_id: str) -> Dict[str, Any]:
        """
         Get metadata about a bucket. This is a wrapper around the Bucket. metadata method

         @param bucket_id - The ID of the bucket to retrieve metadata about

         @return A dictionary of key / value
        """
        """Get metadata about bucket."""
        bucket = self.db[bucket_id]
        return bucket.metadata()

    @check_bucket_exists
    def export_bucket(self, bucket_id: str) -> Dict[str, Any]:
        """
         Export a bucket to a dataformat consistent across versions including all events. This is useful for exporting data that is in an unusual format such as JSON or JSON - serialized data.

         @param bucket_id - The ID of the bucket to export.

         @return The metadata associated with the bucket as a dictionary with keys ` events ` and ` dataformat `
        """
        """Export a bucket to a dataformat consistent across versions, including all events in it."""
        bucket = self.get_bucket_metadata(bucket_id)
        bucket["events"] = self.get_events(bucket_id, limit=-1)
        # Scrub event IDs
        # for event in bucket["events"]:
        #     del event["id"]
        return bucket

    def export_all(self) -> Dict[str, Any]:
        """
         Exports all buckets and their events to a format consistent across versions. This is useful for exporting a set of data that is stored in Amazon S3 and can be used to make sure they are in the correct format


         @return Dictionary of exported buckets
        """
        """Exports all buckets and their events to a format consistent across versions"""
        buckets = self.get_buckets()
        exported_buckets = {}
        # Export the bucket for the current window.
        for key, value in buckets.items():
            # Export the bucket for the given client.
            if value["client"] == "sd-watcher-window":
                id_of_client = value["id"]
                exported_buckets[id_of_client] = self.export_bucket(id_of_client)
        return exported_buckets

    def import_bucket(self, bucket_data: Any):
        """
         Import a bucket into the database. This is a wrapper around db. create_bucket to allow us to pass in bucket_data as a dict instead of a json object.

         @param bucket_data - The data to import into the database
        """
        bucket_id = bucket_data["id"]
        logger.info(f"Importing bucket {bucket_id}")

        # TODO: Check that bucket doesn't already exist
        self.db.create_bucket(
            bucket_id,
            type=bucket_data["type"],
            client=bucket_data["client"],
            hostname=bucket_data["hostname"],
            created=(
                bucket_data["created"]
                if isinstance(bucket_data["created"], datetime)
                else iso8601.parse_date(bucket_data["created"])
            ),
        )

        # scrub IDs from events
        # (otherwise causes weird bugs with no events seemingly imported when importing events exported from sd-server-rust, which contains IDs)
        for event in bucket_data["events"]:
            if "id" in event:
                del event["id"]

        self.create_events(
            bucket_id,
            [Event(**e) if isinstance(e, dict) else e for e in bucket_data["events"]],
        )

    def import_all(self, buckets: Dict[str, Any]):
        """
         Import all buckets into the storage. This is a no - op if there are no buckets to import

         @param buckets - A dictionary of bucket
        """
        # Import all buckets in the bucket
        for bid, bucket in buckets.items():
            self.import_bucket(bucket)

    def create_bucket(

        self,
        bucket_id: str,
        event_type: str,
        client: str,
        hostname: str,
        created: Optional[datetime] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Create a bucket.

        If hostname is "!local", the hostname and device_id will be set from the server info.
        This is useful for watchers which are known/assumed to run locally but might not know their hostname (like sd-watcher-web).

        Returns True if successful, otherwise false if a bucket with the given ID already existed.
        """
        # Create a new datetime object.
        if created is None:
            created = datetime.now()
        # Return true if the bucket is in the database.
        if bucket_id in self.db.buckets():
            return False
        # Get the hostname and device id from the server.
        if hostname == "!local":
            info = self.get_info()
            # If data is not set set to null.
            if data is None:
                data = {}
            hostname = info["hostname"]
            data["device_id"] = info["device_id"]
        self.db.create_bucket(
            bucket_id,
            type=event_type,
            client=client,
            hostname=hostname,
            created=created,
            data=data,
        )
        return True

    @check_bucket_exists
    def update_bucket(

        self,
        bucket_id: str,
        event_type: Optional[str] = None,
        client: Optional[str] = None,
        hostname: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
         Update bucket metadata. This is a low - level method that should be used by clients to keep track of changes to buckets.

         @param bucket_id - Id of bucket to update. Must be unique within the bucket.
         @param event_type - Type of event that triggered this update.
         @param client - Client to send this update to. If not specified the default client will be used.
         @param hostname - Hostname associated with this update. If not specified the default hostname will be used.
         @param data - Dict of key / value pairs to send with this update.

         @return ` ` None ` ` to indicate success or failure
        """
        self.db.update_bucket(
            bucket_id,
            type=event_type,
            client=client,
            hostname=hostname,
            data=data,
        )
        return None

    @check_bucket_exists
    def delete_bucket(self, bucket_id: str) -> None:
        """
         Delete a bucket from the storage. This is a no - op if the bucket does not exist

         @param bucket_id - The ID of the bucket to delete

         @return None The response from the S3 server or None if the bucket doesn't
        """
        """Delete a bucket"""
        self.db.delete_bucket(bucket_id)
        logger.debug(f"Deleted bucket '{bucket_id}'")
        return None

    @check_bucket_exists
    def get_event(
        self,
        bucket_id: str,
        event_id: int,
    ) -> Optional[Event]:
        """
         Get an event from a bucket. This is a GET request to the API

         @param bucket_id - The ID of the bucket
         @param event_id - The ID of the event to retrieve

         @return The event or None if not found ( error in json
        """
        logger.debug(
            f"Received get request for event {event_id} in bucket '{bucket_id}'"
        )
        event = self.db[bucket_id].get_by_id(event_id)
        return event.to_json_dict() if event else None

    @check_bucket_exists
    def get_events(
        self,
        bucket_id: str,
        limit: int = -1,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
    ) -> List[Event]:
        """Get events from a bucket"""
        logger.debug(f"Received get request for events in bucket '{bucket_id}'")
        # This function is used to set the limit to the next call to the server.
        if limit is None:  # Let limit = None also mean "no limit"
            limit = -1
        events = [
            event.to_json_dict() for event in self.db[bucket_id].get(limit, start, end)
        ]
        return events

    @check_bucket_exists
    def create_events(self, bucket_id: str, events: List[Event]) -> Optional[Event]:
        """
         Create events for a bucket. This is a low - level method for use by clients that don't need to worry about event handling.

         @param bucket_id - The bucket to create the events for
         @param events - A list of events to create

         @return The newly created event or None if one was not
        """
        """Create events for a bucket. Can handle both single events and multiple ones.

        Returns the inserted event when a single event was inserted, otherwise None."""
        return self.db[bucket_id].insert(events)

    @check_bucket_exists
    def get_eventcount(

        self,
        bucket_id: str,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
    ) -> int:
        """
         Get eventcount from a bucket. This is a low level method for getting the number of events in a bucket

         @param bucket_id - The id of the bucket
         @param start - The start of the time range to retrieve events from
         @param end - The end of the time range to retrieve events from

         @return The number of events in the time range [ start end
        """
        logger.debug(f"Received get request for eventcount in bucket '{bucket_id}'")
        return self.db[bucket_id].get_eventcount(start, end)

    @check_bucket_exists
    def delete_event(self, bucket_id: str, event_id) -> bool:
        """
         Delete an event from a bucket. This is a destructive operation. You must be sure that there is no event in the bucket before you can delete it

         @param bucket_id - The id of the bucket
         @param event_id - The id of the event

         @return True if the event was deleted False if it was
        """
        """Delete a single event from a bucket"""
        return self.db[bucket_id].delete(event_id)

    @check_bucket_exists
    def heartbeat(self, bucket_id: str, heartbeat: Event, pulsetime: float) -> Event:
        """
         The event to send to the watcher. It must be a : class : ` ~swift. common. events. Event ` object

         @param heartbeat:
         @param bucket_id - The bucket to send the heartbeat to
         @param pulsetime - The pulse time in seconds since the epoch.

         @return The newly created or updated event that was sent to the
        """
        """
        Heartbeats are useful when implementing watchers that simply keep
        track of a state, how long it's in that state and when it changes.
        A single heartbeat always has a duration of zero.

        If the heartbeat was identical to the last (apart from timestamp), then the last event has its duration updated.
        If the heartbeat differed, then a new event is created.

        Such as:
         - Active application and window title
           - Example: sd-watcher-window
         - Currently open document/browser tab/playing song
           - Example: wakatime
           - Example: sd-watcher-web
           - Example: sd-watcher-spotify
         - Is the user active/inactive?
           Send an event on some interval indicating if the user is active or not.
           - Example: sd-watcher-afk

        Inspired by: https://wakatime.com/developers#heartbeats
        """

        if heartbeat["data"]["app"] and heartbeat["data"]["app"] == "afk" and heartbeat["data"]["status"] == "afk":
            store_credentials("is_afk", True)
        elif heartbeat["data"]["app"] and heartbeat["data"]["app"] == "afk" and heartbeat["data"]["status"] != "afk":
            store_credentials("is_afk", False)
        if heartbeat["data"]["app"] and heartbeat["data"]["app"] != "afk"and get_credentials("is_afk"):
            return heartbeat

        logger.debug(
            "Received heartbeat in bucket '{}'\n\ttimestamp: {}, duration: {}, pulsetime: {}\n\tdata: {}".format(
                bucket_id,
                heartbeat.timestamp,
                heartbeat.duration,
                pulsetime,
                heartbeat.data,
            )
        )

        # The endtime here is set such that in the event that the heartbeat is older than an
        # existing event we should try to merge it with the last event before the heartbeat instead.
        # FIXME: This (the endtime=heartbeat.timestamp) gets rid of the "heartbeat was older than last event"
        #        warning and also causes a already existing "newer" event to be overwritten in the
        #        replace_last call below. This is problematic.
        # Solution: This could be solved if we were able to replace arbitrary events.
        #           That way we could double check that the event has been applied
        #           and if it hasn't we simply replace it with the updated counterpart.

        last_event = None
        # Get the last event for the bucket
        if bucket_id not in self.last_event:
            last_events = self.db[bucket_id].get(limit=1)
            # Set last_event to the last event
            if len(last_events) > 0:
                last_event = last_events[0]
        else:
            last_event = self.last_event[bucket_id]

        # This function is called by the heartbeat_merge function.
        if last_event:
            # Heartbeat data is the same as heartbeat. data.
            if last_event.data == heartbeat.data:
                merged = heartbeat_merge(last_event, heartbeat, pulsetime)
                # If heartbeat is valid or after pulse window insert new event.
                if merged is not None:
                    # Heartbeat was merged into last_event
                    logger.debug(
                        "Received valid heartbeat, merging. (bucket: {}) (app: {})".format(
                            bucket_id, merged["data"]["app"]
                        )
                    )
                    self.last_event[bucket_id] = merged
                    self.db[bucket_id].replace_last(merged)
                    return merged
                else:
                    logger.debug(
                        "Received heartbeat after pulse window, inserting as new event. (bucket: {}) (app: {})".format(
                            bucket_id, heartbeat["data"]["app"]
                        )
                    )
            else:
                logger.debug(
                    "Received heartbeat with differing data, inserting as new event. (bucket: {}) (app: {})".format(
                            bucket_id, heartbeat["data"]["app"]
                        )
                )
        else:
            logger.info(
                "Received heartbeat, but bucket was previously empty, inserting as new event. (bucket: {})".format(
                    bucket_id
                )
            )

        heartbeat = self.db[bucket_id].insert(heartbeat)
        self.last_event[bucket_id] = heartbeat
        return heartbeat

    def query2(self, name, query, timeperiods, cache):
        """
         Queries the database for data. This is the second part of the : meth : ` ~oldman. query ` method.

         @param name - The name of the database to query. This is used to create the query and to access the database in the cache.
         @param query - The query to be executed. This is a list of strings where each string is a field in the database and each field is a value in the form
         @param timeperiods
         @param cache
        """
        result = []
        # Create a query for each timeperiod in the list of timeperiods.
        for timeperiod in timeperiods:
            period = timeperiod.split("/")[
                :2
            ]  # iso8601 timeperiods are separated by a slash
            starttime = iso8601.parse_date(period[0])
            endtime = iso8601.parse_date(period[1])
            query = "".join(query)
            result.append(query2.query(name, query, starttime, endtime, self.db))
        return result

    # TODO: Right now the log format on disk has to be JSON, this is hard to read by humans...
    def get_log(self):
        """Get the server log in json format"""
        payload = []
        with open(get_log_file_path()) as log_file:
            for line in log_file.readlines()[::-1]:
                payload.append(json.loads(line))
        return payload, 200

    def get_dashboard_events(
        self,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
    ) -> List[Event]:
        events = self.db.get_dashboard_events(starttime=start,endtime=end)
        # print("eventssssss", events)
        # groupedEvents = group_events_by_application(events)   

        if len(events) > 0:
            event_start = parser.isoparse(events[0]["timestamp"])
            start_hour = event_start.hour
            start_min = event_start.minute
            start_date_time = event_start

            # Convert events list to JSON object using custom serializer
            events_json = json.dumps({
                "events": events,
                "start_hour": start_hour,
                "start_min": start_min,
                "start_date_time": start_date_time,
                # "groupedEvents" : groupedEvents
            }, default=datetime_serializer)

            return json.loads(events_json)
        else: return None

    def get_non_sync_events(self) -> List[Event]:
        events = self.db.get_non_sync_events()
        if not events:
            logger.info("No unsynced events found.")
            return {"status": "NoEvents", "events": []}
        try:
            event_start = parser.isoparse(events[0]["timestamp"])
            events_json = json.dumps({
                "events": events,
                "start_hour": event_start.hour,
                "start_min": event_start.minute,
                "start_date_time": event_start,
            }, default=datetime_serializer)
            return json.loads(events_json)
        except Exception as e:
            logger.error(f"Error parsing events: {e}")
            return {"status": "error", "message": str(e)}

    def get_most_used_apps(
        self,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
    ) -> List[Event]:

        most_used_apps = self.db.get_most_used_apps(starttime=start,endtime=end)

        if len(most_used_apps) > 0:
            events_json = json.dumps({
                "most_used_apps" : most_used_apps
            }, default=datetime_serializer)
            return json.loads(events_json)
        else: return None

    @check_bucket_exists
    def get_formated_events(
        self,
        bucket_id: str,
        limit: int = -1,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
    ) -> List[Event]:
        events = self.db.get_dashboard_events(starttime=start,endtime=end)

        current_date = datetime.now().date()
        start_of_day = datetime.combine(current_date, datetime.min.time())
        end_of_day = datetime.combine(current_date, datetime.max.time())
        most_used_apps = self.db.get_most_used_apps(starttime=start_of_day,endtime=end_of_day)

        if len(events) > 0:
            event_start = parser.isoparse(events[0]["timestamp"])
            start_hour = event_start.hour
            start_min = event_start.minute
            start_date_time = event_start

            # Convert events list to JSON object using custom serializer
            events_json = json.dumps({
                "events": events,
                "start_hour": start_hour,
                "start_min": start_min,
                "start_date_time": start_date_time,
                "most_used_apps" : most_used_apps
            }, default=datetime_serializer)

            return json.loads(events_json)
        else: return None

def datetime_serializer(obj):
    """
     Serialize datetime to ISO format. This is used to ensure that dates are converted to ISO format before saving to the database.

     @param obj - The object to serialize. If it is a : class : ` datetime. datetime ` it will be returned as is.

     @return The object serialized as ISO format or ` ` None
    """
    # Return the ISO 8601 format of the object.
    if isinstance(obj, datetime):
        return obj.isoformat()




def event_filter(most_used_apps,data):
    """
        Filter events to include only those that don't have lock apps or login windows

        @param most_used_apps - list of apps that are most used
        @param data - list of events from json file that we want to filter

        @return a list of formatted events for use in event_
    """

    # Convert data to JSON object.
    if (
        isinstance(data, list)
        and len(data) > 0
    ):
        events = sorted(data, key=lambda x: parser.isoparse(x["timestamp"]).timestamp())
        formated_events = []
        start_date_time = None
        start_hour = 24
        start_min = 59

        # This function will add events to the event list
        for e in events:
            # This function is called by the app when the event is triggered.
            if not "LockApp" in e['data']['app'] and not "loginwindow" in e['data']['app']:
                event_start = parser.isoparse(e["timestamp"])
                event_end = event_start + timedelta(seconds=e["duration"])
                # color = getRandomColorVariants()  # Assuming you have this function implemented

                new_event = {
                    **e,
                    "start": event_start.isoformat(),
                    "end": event_end.isoformat(),
                    "event_id": e["id"],
                    "title": e["data"].get("title", ""),
                    # "light": color["light"],
                    # "dark": color["dark"],
                }
                formated_events.append(new_event)

                # Set the start time of the event.
                if start_hour > event_start.hour or (start_hour == event_start.hour and start_min > event_start.minute):
                    start_hour = event_start.hour
                    start_min = event_start.minute
                    start_date_time = event_start

        # Convert events list to JSON object using custom serializer
        events_json = json.dumps({
            "events": formated_events,
            "start_hour": start_hour,
            "start_min": start_min,
            "start_date_time": start_date_time,
            "most_used_apps" : most_used_apps
        }, default=datetime_serializer)

        return json.loads(events_json)  # Parse the JSON string to a Python object


class RalvieServerQueue(threading.Thread):
    def __init__(self, server: ServerAPI) -> None:
        super().__init__(daemon=True)  # Initialize as a daemon thread

        self.server = server
        self.userId = ""
        self.connected = False
        self._stop_event = threading.Event()
        self._attempt_reconnect_interval = 10  # Interval between reconnection attempts

    def _try_connect(self) -> bool:
        try:
            cache_key = "Sundial"
            cached_credentials = cache_user_credentials(cache_key)
            if cached_credentials:
                db_key = cached_credentials.get("encrypted_db_key")
                user_key = load_key("user_key")
                self.userId = load_key("userId")

                if db_key and user_key and self.userId:
                    self.connected = True
                    return True
                else:
                    logger.warning("Missing necessary keys for connection.")
            self.connected = False
        except Exception as e:
            logger.error(f"Failed to connect: {e}")
            self.connected = False
        return self.connected

    def wait(self, seconds: int) -> bool:
        return self._stop_event.wait(seconds)

    def should_stop(self) -> bool:
        return self._stop_event.is_set()

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        # Attempt to establish a connection on start
        if not self._try_connect():
            logger.info("Initial connection attempt failed. Will retry.")

        while not self.should_stop():
            # Check internet connection and attempt to sync
            if is_internet_connected():
                if not self.connected:
                    logger.info("Attempting to reconnect...")
                    self._try_connect()

                if self.connected:
                    logger.info("Connected to internet. Attempting to sync events.")
                    try:
                        sync_result = self.server.sync_events_to_ralvie()
                        logger.info(f"Sync result: {sync_result}")
                    except Exception as e:
                        logger.error(f"Error during sync: {e}")
                else:
                    logger.warning("Not connected. Retrying in a few seconds.")
            else:
                logger.warning("No internet connection. Waiting to retry...")

            # Wait for the defined interval before trying again, respecting stop events.
            self.wait(300)


def group_events_by_application(events):
    grouped_events = {}

    for event in events:
        timestamp = datetime.fromisoformat(event["start"])
        rounded_timestamp = timestamp - timedelta(minutes=timestamp.minute % 30, seconds=timestamp.second, microseconds=timestamp.microsecond)
        key = (event["application_name"], rounded_timestamp)

        if key not in grouped_events:
            grouped_events[key] = {
                "application_name": event["application_name"],
                "start": rounded_timestamp.isoformat() + "Z",
                "end": rounded_timestamp + timedelta(minutes=30),
                "total_duration": 0,
                "events": []
            }

        grouped_events[key]["total_duration"] += event["duration"]
        grouped_events[key]["events"].append({
            "event_id": event["event_id"],
            "duration": event["duration"],
            "timestamp": event["timestamp"],
            "data": event["data"],
            "id": event["id"],
            "bucket_id": event["bucket_id"],
            "app": event["app"],
            "title": event["title"],
            "url": event["url"]
        })

    # Flatten the nested structure into a single list
    result_list = list(grouped_events.values())

    return result_list



