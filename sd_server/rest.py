import getpass
import os
import traceback
from functools import wraps
from threading import Lock
from typing import Dict
import sys
import pytz
import numpy as np
from tzlocal import get_localzone
from xhtml2pdf import pisa
from dateutil.parser import parse
from sd_core.launch_start import delete_launch_app, launch_app, check_startup_status, set_autostart_registry
from sd_core.util import authenticate, is_internet_connected, reset_user
import pandas as pd
from datetime import datetime, timedelta, date, time
import iso8601
from sd_core import schema, db_cache
from sd_core.models import Event
from sd_core.cache import *
from sd_query.exceptions import QueryException
from flask import (
    Blueprint,
    current_app,
    jsonify,
    make_response,
    request,
)
from flask_restx import Api, Resource, fields
import jwt
from io import BytesIO
from . import logger
from .api import ServerAPI
from .exceptions import BadRequest, Unauthorized
from sd_qt.manager import Manager
from sd_datastore.storages.peewee import blocked_apps,blocked_url

application_cache_key = "application_cache"
manager = Manager()

def get_potential_location_and_zone(minutes_difference):
    """
    Attempts to guess potential time zone based on assumed reference time
    (UTC now) and time difference.

    Args:
        minutes_difference: The difference in minutes from the assumed reference time.

    Returns:
        A list of potential time zone objects, or None if information is missing.
    """

    # Assume reference time as UTC now (adjust as needed)
    reference_time = datetime.utcnow()

    # Calculate target time by adjusting reference time with minute difference
    target_time = reference_time - timedelta(minutes=minutes_difference)

    # Get potential offset based on minute difference (adjust as needed)
    offset_minutes = minutes_difference % 60
    offset_hours = (minutes_difference - offset_minutes) // 60
    potential_offset = pytz.FixedOffset(offset_minutes)

    # Consider all zones with the potential offset
    potential_zones = [zone for zone in pytz.all_timezones
                        if zone.localize(datetime.now()).utcoffset() == potential_offset]

    return potential_zones


def host_header_check(f):
    """
        Check if token is valid. This is a decorator for API methods that need to be decorated in order to check the token in the Host header

        @param f - function to be decorated with this

        @return tuple of ( token error
    """

    @wraps(f)
    def decorator(*args, **kwargs):
        """
         Decorate to check token. This is a decorator that can be used as a context manager or in a class decorator.


         @return tuple of JSON response and status code. If status code is 0 it means success
        """
        excluded_paths = [
            '/api/0/buckets/',
            '/api/swagger.json', '/api/0/ralvie/login','/api/0/ralvie/refresh_token',
            '/api/0/login', '/api/0/user'
        ]
        # This method is used to check if the request is valid and if the request is a heartbeat credentials and the request is not a valid credentials.
        if "/heartbeat" not in request.path and "/credentials" not in request.path and request.path not in excluded_paths and request.method != 'OPTIONS':
            token = request.headers.get("Authorization")
            # This method is used to validate the token.
            if not token:
                logging.warning("Token is missing")
                return {"message": "Token is missing"}, 401
            elif "/company" not in request.path:
                cache_key = "Sundial"
                cached_credentials = cache_user_credentials(cache_key, "SD_KEYS")
                if cached_credentials is not None:
                    user_key = cached_credentials.get("user_key")
                    try:
                        jwt.decode(token.replace("Bearer ", ""), key=user_key, algorithms=["HS256"])
                    except jwt.InvalidTokenError as e:
                        logging.error("Invalid token")
                        return {"message": "Invalid token"}, 401
                else:
                    user_key=None
                    logger.info("cache credentials are None at the time.system checking....please login")

        server_host = current_app.config["HOST"]
        req_host = request.headers.get("host", None)
        # Check if server is listening on 0. 0. 0. 0. 0. 0 host header check is disabled.
        if server_host == "0.0.0.0":
            logging.warning(
                "Server is listening on 0.0.0.0, host header check is disabled (potential security issue)."
            )
        elif req_host is None:
            return {"message": "host header is missing"}, 400
        elif req_host.split(":")[0] not in ["localhost", "127.0.0.1", server_host]:
            return {"message": f"host header is invalid (was {req_host})"}, 400

        return f(*args, **kwargs)

    return decorator


authorizations = {
    'Bearer': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization',
    }
}
blueprint = Blueprint("api", __name__, url_prefix="/api")
api = Api(blueprint, doc="/", decorators=[host_header_check], authorizations=authorizations)

# Loads event and bucket schema from JSONSchema in sd_core
event = api.schema_model("Event", schema.get_json_schema("event"))
bucket = api.schema_model("Bucket", schema.get_json_schema("bucket"))
buckets_export = api.schema_model("Export", schema.get_json_schema("export"))

# TODO: Construct all the models from JSONSchema?
#       A downside to contructing from JSONSchema: flask-restplus does not have marshalling support

info = api.model(
    "Info",
    {
        "hostname": fields.String(),
        "version": fields.String(),
        "testing": fields.Boolean(),
        "device_id": fields.String(),
    },
)

create_bucket = api.model(
    "CreateBucket",
    {
        "client": fields.String(required=True),
        "type": fields.String(required=True),
        "hostname": fields.String(required=True),
    },
)

update_bucket = api.model(
    "UpdateBucket",
    {
        "client": fields.String(required=False),
        "type": fields.String(required=False),
        "hostname": fields.String(required=False),
        "data": fields.String(required=False),
    },
)

query = api.model(
    "Query",
    {
        "timeperiods": fields.List(
            fields.String, required=True, description="List of periods to query"
        ),
        "query": fields.List(
            fields.String, required=True, description="String list of query statements"
        ),
    },
)


def copy_doc(api_method):
    """
     Copy docstrings from another function to the decorated function. Used to copy docstrings in ServerAPI over to the flask - restplus Resources.

     @param api_method - The method to copy the docstrings from.

     @return A decorator that copies the docstrings from the decorated function
    """
    """Decorator that copies another functions docstring to the decorated function.
    Used to copy the docstrings in ServerAPI over to the flask-restplus Resources.
    (The copied docstrings are then used by flask-restplus/swagger)"""

    def decorator(f):
        """
         Decorate a function to add documentation. This is useful for methods that are decorated with @api_method

         @param f - The function to decorate.

         @return The decorated function as a decorator ( not a decorator
        """
        f.__doc__ = api_method.__doc__
        return f

    return decorator


# SERVER INFO
def format_duration(duration):
    """
     Format duration in human readable format. This is used to format durations when logging to logcat

     @param duration - The duration to format.

     @return A string representing the duration in human readable format e. g
    """
    # Format duration in H m s format.
    if duration is not None:
        seconds = int(duration)
        d = seconds // (3600 * 24)
        h = seconds // 3600 % 24
        m = seconds % 3600 // 60
        s = seconds % 3600 % 60
        # Returns a string representation of the H m s.
        if h > 0:
            return '{:02d}H {:02d}m {:02d}s'.format(h, m, s)
        elif m > 0:
            return '{:02d}m {:02d}s'.format(m, s)
        elif s > 0:
            return '{:02d}s'.format(s)
    return '1s'


@api.route("/0/info")
class InfoResource(Resource):
    @api.doc(security="Bearer")
    @api.marshal_with(info)
    @copy_doc(ServerAPI.get_info)
    def get(self) -> Dict[str, Dict]:
        """
         Get information about the application. This is a shortcut for : meth : ` flask. api. get_info `.


         @return A dictionary of application information or an empty dictionary if there is no information
        """
        return current_app.api.get_info()


# Users


@api.route("/0/user")
class UserResource(Resource):
    @api.doc(security="Bearer")
    def post(self):
        """
         Create a Sundial user. This is a POST request to the / v1 / users endpoint.


         @return a dictionary containing the user's details and a boolean indicating if the user was
        """
        cache_key = "Sundial"
        cached_credentials = cache_user_credentials(cache_key, "SD_KEYS")
        # If internet connection is not connected to internet and try again.
        if not is_internet_connected():
            print("Please connect to internet and try again.")
        data = request.get_json()
        # Returns a 400 if the user is not a valid email or password
        if not data['email']:
            return {"message": "User name is mandatory"}, 400
        elif not data['password']:
            return {"message": "Password is mandatory"}, 400
        # Returns the user who is currently using the cached credentials.
        if cached_credentials is not None:
            user = cached_credentials.get("encrypted_db_key")
        else:
            user = None
        # Create a user and authorize it
        if True:
            result = current_app.api.create_user(data)
            # This method is used to authorize and create a company.
            if result.status_code == 200 and json.loads(result.text)["code"] == 'UASI0001':
                userPayload = {
                    "userName": data['email'],
                    "password": data['password']
                }
                authResult = current_app.api.authorize(userPayload)

                # Returns the auth result as JSON
                if 'company' not in data:
                    return json.loads(authResult.text), 200

                # This method is used to create a company and create a company
                if authResult.status_code == 200 and json.loads(authResult.text)["code"] == 'RCI0000':
                    token = json.loads(authResult.text)["data"]["access_token"]
                    id = json.loads(authResult.text)["data"]["id"]
                    companyPayload = {
                        "name": data['company'],
                        "code": data['company'],
                        "status": "ACTIVE"
                    }

                    companyResult = current_app.api.create_company(companyPayload, 'Bearer ' + token)

                    # This method is called when the user is created
                    if companyResult.status_code == 200 and json.loads(companyResult.text)["code"] == 'UASI0006':
                        current_app.api.get_user_credentials(id, 'Bearer ' + token)
                        init_db = current_app.api.init_db()
                        # This function is called when the user is created
                        if init_db:
                            return {"message": "Account created successfully"}, 200
                        else:
                            reset_user()
                            return {"message": "Something went wrong"}, 500
                    else:
                        return json.loads(companyResult.text), 200
                else:
                    return json.loads(authResult.text), 200
            else:
                return json.loads(result.text), 200
        else:
            return {"message": "User already exist"}, 200


@api.route("/0/company")
class CompanyResource(Resource):
    def post(self):
        """
         Create a company in UASI. This will be used for creating company in UASI.


         @return tuple of ( response status_code ) where response is empty if success or a dict with error
        """
        data = request.get_json()
        token = request.headers.get("Authorization")
        # If token is not set return 401
        if not token:
            return {"message": "Token is required"}, 401
        # Error message if name is not set
        if not data['name']:
            return {"message": "Company name is mandatory"}, 400
        companyPayload = {
            "name": data['name'],
            "code": data['code'],
            "status": "ACTIVE"
        }

        companyResult = current_app.api.create_company(companyPayload, token)

        # Returns the status code of the company result.
        if companyResult.status_code == 200 and json.loads(companyResult.text)["code"] == 'UASI0006':
            return json.loads(companyResult.text), 200
        else:
            return json.loads(companyResult.text), companyResult.status_code


# Login by system credentials
@api.route("/0/login")
class LoginResource(Resource):
    def post(self):
        """
         Authenticate and encode user credentials. This is a POST request to / api / v1 / Sundial


         @return Response code and JSON
        """
        data = request.get_json()
        cache_key = "Sundial"
        cached_credentials = cache_user_credentials(cache_key, "SD_KEYS")
        user_key = cached_credentials.get("user_key")

        # Returns a JSON object with the user_key data.
        if user_key:
            # Authenticates the user with the given data.
            if authenticate(data['userName'], data['password']):
                encoded_jwt = jwt.encode({"user": data['userName'], "email": cached_credentials.get("email"),
                                          "phone": cached_credentials.get("phone")}, user_key, algorithm="HS256")
                return {"code": "SDI0000", "message": "Success", "data": {"token": encoded_jwt}}, 200
            else:
                return {"code": "SDE0000", "message": "Username or password is wrong"}, 200
        else:
            return {"message": "User does not exist"}, 200

    def get(self):
        """
         Get method for Sundial. json API. This method is used to check if user exist or not.


         @return 200 if user exist 401 if user does not exist
        """
        data = request.get_json()
        cache_key = "Sundial"
        cached_credentials = cache_user_credentials(cache_key, "SD_KEYS")
        # Returns the encrypted_db_key if the cached credentials are cached.
        if cached_credentials is not None:
            user_key = cached_credentials.get("encrypted_db_key")
        else:
            user_key = None
        # Returns a 200 if user_key is not found 401 if user_key is not present
        if user_key:
            return {"message": "User exist"}, 200
        else:
            return {"message": "User does not exist"}, 401


# Login by ralvie cloud
@api.route("/0/ralvie/login")
class RalvieLoginResource(Resource):
    def post(self):
        """
         Authenticate and log in a user. This is the endpoint for authenticating and log in a user.


         @return A JSON with the result of the authentication and user
        """
        cache_key = "Sundial"
        # Check Internet Connectivity
        response_data = {}
        # If the internet is not connected return a 200 error message.
        if not is_internet_connected():
            return jsonify({"message": "Please connect to the internet and try again."}), 200

        # Parse Request Data
        data = request.get_json()
        user_name = data.get('userName')
        password = data.get('password')

        # JSON response with user_name password user_name user_name password
        if not user_name:
            return jsonify({"message": "User name is mandatory"}), 400
        elif not password:
            return jsonify({"message": "Password is mandatory"}), 400

        # Reset User Data
        reset_user()

        # Authenticate User
        auth_result = current_app.api.authorize(data)

        # Returns a JSON response with the user credentials.
        if auth_result.status_code == 200 and json.loads(auth_result.text)["code"] == 'UASI0011':
            # Retrieve Cached User Credentials
            cached_credentials = cache_user_credentials(cache_key, "SD_KEYS")

            # Get the User Key
            user_key = cached_credentials.get("encrypted_db_key") if cached_credentials else None

            # This function is used to get user credentials from the user_key
            if user_key is None:
                token = json.loads(auth_result.text)["data"]["access_token"]
                refresh_token = json.loads(auth_result.text)["data"]["refresh_token"]
                user_id = json.loads(auth_result.text)["data"]["id"]
                current_app.api.get_user_credentials(user_id, 'Bearer ' + token)
                init_db = current_app.api.init_db()

                # Reset the user to the default user
                if not init_db:
                    reset_user()
                    return {"message": "Something went wrong"}, 500

            # Generate JWT
            payload = {
                "user": getpass.getuser(),
                "email": cache_user_credentials(cache_key, "SD_KEYS").get("email"),
                "phone": cache_user_credentials(cache_key, "SD_KEYS").get("phone")
            }
            encoded_jwt = jwt.encode(payload, cache_user_credentials(cache_key, "SD_KEYS").get("user_key"),
                                     algorithm="HS256")

            # Response
            response_data['code'] = "UASI0011",
            response_data["message"] = json.loads(auth_result.text)["message"],
            response_data["data"]: {"token": "Bearer " + encoded_jwt}
            return {"code": "UASI0011", "message": json.loads(auth_result.text)["message"],
                    "data": {"token": "Bearer " + encoded_jwt, "access_token": "Bearer " + token, "refresh_token": refresh_token}}, 200
        else:
            return {"code": json.loads(auth_result.text)["code"], "message": json.loads(auth_result.text)["message"],
                    "data": json.loads(auth_result.text)["data"]}, 200


# BUCKETS

@api.route("/0/buckets/<string:bucket_id>/formated_events")
class EventsResource(Resource):
    # For some reason this doesn't work with the JSONSchema variant
    # Marshalling doesn't work with JSONSchema events
    # @api.marshal_list_with(event)
    @api.doc(model=event)
    @api.param("limit", "the maximum number of requests to get")
    @api.param("start", "Start date of events")
    @api.param("end", "End date of events")
    @copy_doc(ServerAPI.get_events)
    def get(self, bucket_id):
        """
         Get events for a bucket. This endpoint is used to retrieve events that have been submitted to the API for a given bucket.

         @param bucket_id - the id of the bucket to retrieve events for

         @return a tuple of ( events status
        """
        args = request.args
        limit = int(args["limit"]) if "limit" in args else -1
        start = iso8601.parse_date(args["start"]) if "start" in args else None
        end = iso8601.parse_date(args["end"]) if "end" in args else None

        events = current_app.api.get_formated_events(
            bucket_id, limit=limit, start=start, end=end
        )
        return events, 200

    # TODO: How to tell expect that it could be a list of events? Until then we can't use validate.
    @api.expect(event)
    @copy_doc(ServerAPI.create_events)
    def post(self, bucket_id):
        """
         Create events in a bucket. This endpoint is used to create one or more events in a bucket.

         @param bucket_id - ID of bucket to create events in

         @return JSON representation of the created event or HTTP status code
        """
        data = request.get_json()
        logger.debug(
            "Received post request for event in bucket '{}' and data: {}".format(
                bucket_id, data
            )
        )

        # Convert a POST data to a list of events.
        if isinstance(data, dict):
            events = [Event(**data)]
        elif isinstance(data, list):
            events = [Event(**e) for e in data]
        else:
            raise BadRequest("Invalid POST data", "")
        event = current_app.api.create_events(bucket_id, events)
        return event.to_json_dict() if event else None, 200


@api.route("/0/buckets/")
class BucketsResource(Resource):
    # TODO: Add response marshalling/validation
    @copy_doc(ServerAPI.get_buckets)
    def get(self) -> Dict[str, Dict]:
        """
         Get all buckets. This is a shortcut to : meth : ` ~flask. api. Baskets. get_buckets `.


         @return A dictionary of bucket names and their values keyed by bucket
        """
        return current_app.api.get_buckets()


@api.route("/0/buckets/<string:bucket_id>")
class BucketResource(Resource):
    @api.doc(model=bucket)
    @copy_doc(ServerAPI.get_bucket_metadata)
    def get(self, bucket_id):
        """
         Get metadata for a bucket. This is a GET request to the ` ` S3_bucket_metadata ` ` endpoint.

         @param bucket_id - the ID of the bucket to get metadata for

         @return a dict containing bucket metadata or None if not found
        """
        return current_app.api.get_bucket_metadata(bucket_id)

    @api.expect(create_bucket)
    @copy_doc(ServerAPI.create_bucket)
    def post(self, bucket_id):
        """
         Create a bucket. This endpoint requires authentication and will return a 204 if the bucket was created or a 304 if it already exists.

         @param bucket_id - the id of the bucket to create

         @return http code 200 if bucket was created 304 if it
        """
        data = request.get_json()
        bucket_created = current_app.api.create_bucket(
            bucket_id,
            event_type=data["type"],
            client=data["client"],
            hostname=data["hostname"],
        )
        # Returns a 200 if bucket was created
        if bucket_created:
            return {}, 200
        else:
            return {}, 304

    @api.expect(update_bucket)
    @copy_doc(ServerAPI.update_bucket)
    def put(self, bucket_id):
        """
         Update a bucket. This endpoint is used to update an existing bucket. The request must be made with a JSON object in the body and the data field will be updated to the new data.

         @param bucket_id - the ID of the bucket to update

         @return a 200 response with the updated bucket or an error
        """
        data = request.get_json()
        current_app.api.update_bucket(
            bucket_id,
            event_type=data["type"],
            client=data["client"],
            hostname=data["hostname"],
            data=data["data"],
        )
        return {}, 200

    @copy_doc(ServerAPI.delete_bucket)
    @api.param("force", "Needs to be =1 to delete a bucket it non-testing mode")
    def delete(self, bucket_id):
        """
         Delete a bucket. Only allowed if sd - server is running in testing mode

         @param bucket_id - ID of bucket to delete

         @return 200 if successful 404 if not ( or on error
        """
        args = request.args
        # DeleteBucketUnauthorized if sd server is running in testing mode or if sd server is running in testing mode or if force 1
        if not current_app.api.testing:
            # DeleteBucketUnauthorized if sd server is running in testing mode or if force 1
            if "force" not in args or args["force"] != "1":
                msg = "Deleting buckets is only permitted if sd-server is running in testing mode or if ?force=1"
                raise Unauthorized("DeleteBucketUnauthorized", msg)

        current_app.api.delete_bucket(bucket_id)
        return {}, 200


# EVENTS


@api.route("/0/buckets/<string:bucket_id>/events")
class EventsResource(Resource):
    # For some reason this doesn't work with the JSONSchema variant
    # Marshalling doesn't work with JSONSchema events
    # @api.marshal_list_with(event)
    @api.doc(model=event)
    @api.param("limit", "the maximum number of requests to get")
    @api.param("start", "Start date of events")
    @api.param("end", "End date of events")
    @copy_doc(ServerAPI.get_events)
    def get(self, bucket_id):
        """
         Get events for a bucket. This endpoint is used to retrieve events that have occurred since the last call to : func : ` ~flask. api. Bucket. create `.

         @param bucket_id - the bucket to get events for.

         @return 200 OK with events in JSON. Example request **. : http Example response **. :
        """
        args = request.args
        limit = int(args["limit"]) if "limit" in args else -1
        start = iso8601.parse_date(args["start"]) if "start" in args else None
        end = iso8601.parse_date(args["end"]) if "end" in args else None

        events = current_app.api.get_events(
            bucket_id, limit=limit, start=start, end=end
        )
        return events, 200

    # TODO: How to tell expect that it could be a list of events? Until then we can't use validate.
    @api.expect(event)
    @copy_doc(ServerAPI.create_events)
    def post(self, bucket_id):
        """
         Create events in a bucket. This endpoint is used to create one or more events in a bucket.

         @param bucket_id - ID of bucket to create events in

         @return JSON representation of the created event or HTTP status code
        """
        data = request.get_json()
        logger.debug(
            "Received post request for event in bucket '{}' and data: {}".format(
                bucket_id, data
            )
        )

        # Convert a POST data to a list of events.
        if isinstance(data, dict):
            events = [Event(**data)]
        elif isinstance(data, list):
            events = [Event(**e) for e in data]
        else:
            raise BadRequest("Invalid POST data", "")

        event = current_app.api.create_events(bucket_id, events)
        return event.to_json_dict() if event else None, 200


@api.route("/0/buckets/<string:bucket_id>/events/count")
class EventCountResource(Resource):
    @api.doc(model=fields.Integer)
    @api.param("start", "Start date of eventcount")
    @api.param("end", "End date of eventcount")
    @copy_doc(ServerAPI.get_eventcount)
    def get(self, bucket_id):
        args = request.args
        start = iso8601.parse_date(args["start"]) if "start" in args else None
        end = iso8601.parse_date(args["end"]) if "end" in args else None

        events = current_app.api.get_eventcount(bucket_id, start=start, end=end)
        return events, 200


@api.route("/0/buckets/<string:bucket_id>/events/<int:event_id>")
class EventResource(Resource):
    @api.doc(model=event)
    @copy_doc(ServerAPI.get_event)
    def get(self, bucket_id: str, event_id: int):
        """
         Get an event by bucket and event id. This is an endpoint for GET requests that need to be handled by the client.

         @param bucket_id - ID of the bucket containing the event
         @param event_id - ID of the event to retrieve

         @return A tuple of HTTP status code and the event if
        """
        logger.debug(
            f"Received get request for event with id '{event_id}' in bucket '{bucket_id}'"
        )
        event = current_app.api.get_event(bucket_id, event_id)
        # Return event and response code
        if event:
            return event, 200
        else:
            return None, 404

    @copy_doc(ServerAPI.delete_event)
    def delete(self, bucket_id: str, event_id: int):
        """
         Delete an event from a bucket. This is a DELETE request to / api / v1 / bucket_ids

         @param bucket_id - ID of bucket to delete event from
         @param event_id - ID of event to delete from bucket

         @return JSON with " success " as a boolean and " message " as
        """
        logger.debug(
            "Received delete request for event with id '{}' in bucket '{}'".format(
                event_id, bucket_id
            )
        )
        success = current_app.api.delete_event(bucket_id, event_id)
        return {"success": success}, 200


@api.route("/0/buckets/<string:bucket_id>/heartbeat")
class HeartbeatResource(Resource):
    def __init__(self, *args, **kwargs):
        """
         Initialize the object. This is the first thing to do before the object is created
        """
        self.lock = Lock()
        super().__init__(*args, **kwargs)

    @api.expect(event, validate=True)
    @api.param(
        "pulsetime", "Largest timewindow allowed between heartbeats for them to merge"
    )
    @copy_doc(ServerAPI.heartbeat)
    def post(self, bucket_id):
        """
        Sends a heartbeat to Sundial. This is an endpoint that can be used to check if an event is active and if it is the case.
        @param bucket_id - The ID of the bucket to send the heartbeat to.
        @return 200 OK if heartbeats were sent 400 Bad Request if there is no credentials in
        """
        heartbeat_data = request.get_json()
        if heartbeat_data['data']['title']=='':
            heartbeat_data['data']['title']=heartbeat_data['data']['app']

        if heartbeat_data['data']['app'] in ['ApplicationFrameHost.exe']:
            heartbeat_data['data']['app'] = heartbeat_data['data']['title'] + '.exe'

        # Set default title using the value of 'app' attribute if it's not present in the data dictionary
        settings = db_cache.retrieve("settings_cache")
        if not settings:
            db_cache.store("settings_cache",current_app.api.retrieve_all_settings())
        settings_code = settings.get("weekdays_schedule",{})
        schedule = settings.get("schedule",{})

        true_week_values = [key.lower() for key, value in settings_code.items() if value is True]

        if settings_code.get("starttime") and settings_code.get("endtime"):
            try:
                start_time_str = settings_code.get("starttime")
                end_time_str = settings_code.get("endtime")

                s_time_obj = datetime.strptime(start_time_str, "%I:%M %p")
                e_time_obj = datetime.strptime(end_time_str, "%I:%M %p")

                local_start_time = s_time_obj.strftime("%H:%M")
                local_end_time = e_time_obj.strftime("%H:%M")

                # local_start_time_str = "17:57"
                # Get the current date
                current_date = datetime.now().date()
                day_name = current_date.strftime("%A")
                # Parse the time string and create a datetime object with the current date
                local_start_time = datetime.strptime(f"{current_date} {local_start_time}", "%Y-%m-%d %H:%M")
                local_end_time = datetime.strptime(f"{current_date} {local_end_time}", "%Y-%m-%d %H:%M")

                # Now local_start_time is a datetime object, you can use astimezone method
                start_utc_time = local_start_time.astimezone(pytz.utc)
                end_utc_time = local_end_time.astimezone(pytz.utc)
            except json.JSONDecodeError:
                logger.info("Error: Failed to decode JSON string")

        # Check if schedule is true and contains weekdays
        current_time_utc = datetime.now(pytz.utc)
        if schedule and (day_name.lower() in true_week_values) and not (start_utc_time <= current_time_utc <= end_utc_time):
            return {"message": "Skipping data capture."}, 200
            # Capture data
        heartbeat = Event(**heartbeat_data)

        cache_key = "Sundial"
        cached_credentials = cache_user_credentials(cache_key, "SD_KEYS")
        # Returns cached credentials if cached credentials are not cached.
        if cached_credentials is None:
            return {"message": "No cached credentials."}, 400

        # The pulsetime parameter is required.
        pulsetime = float(request.args["pulsetime"]) if "pulsetime" in request.args else None
        if pulsetime is None:
            return {"message": "Missing required parameter pulsetime"}, 400

        # This lock is meant to ensure that only one heartbeat is processed at a time,
        # as the heartbeat function is not thread-safe.
        # This should maybe be moved into the api.py file instead (but would be very messy).
        if not self.lock.acquire(timeout=1):
            logger.warning(
                "Heartbeat lock could not be acquired within a reasonable time, this likely indicates a bug."
            )
            return {"message": "Failed to acquire heartbeat lock."}, 500
        try:
            event = current_app.api.heartbeat(bucket_id, heartbeat, pulsetime)
        finally:
            self.lock.release()

        if event:
            return event.to_json_dict(), 200
        elif not event:
            return "event not occured"
        else:
            return {"message": "Heartbeat failed."}, 500




# QUERY


@api.route("/0/query/")
class QueryResource(Resource):
    # TODO Docs
    @api.expect(query, validate=True)
    @api.param("name", "Name of the query (required if using cache)")
    def post(self):
        """
         Query an API. This is a POST request to the API endpoint. The query is a JSON object with the following fields : query : the query to be executed timeperiods : the time periods of the query


         @return a JSON object with the results of the query or an error
        """
        name = ""
        # name is the name of the request
        if "name" in request.args:
            name = request.args["name"]
        query = request.get_json()
        try:
            result = current_app.api.query2(
                name, query["query"], query["timeperiods"], False
            )
            return jsonify(result)
        except QueryException as qe:
            traceback.print_exc()
            return {"type": type(qe).__name__, "message": str(qe)}, 400


def removeprotocals(url):
    parts = url.split('//')
    if len(parts) > 1:
        return parts[1]
    else:
        return url
# EXPORT AND IMPORT
def blocked_list():
    # Initialize the blocked_apps dictionary with empty lists for 'app' and 'url'
    blocked_apps = {"app": [], "url": []}

    # Retrieve application blocking information from the cache
    application_blocked = db_cache.retrieve(application_cache_key)
    if not application_blocked:
        db_cache.store(application_cache_key, current_app.api.application_list())

    if application_blocked:
        # Iterate over each application in the 'app' list
        for app_info in application_blocked.get('app', []):
            # Check if the application is blocked
            if app_info.get('is_blocked', False):
                # If the application is blocked, append its name to the 'app' list in blocked_apps
                app_name = app_info['name']
                if platform.system() == 'Windows':
                    app_name += ".exe"  # Append ".exe" for Windows
                blocked_apps['app'].append(app_name)

        # Iterate over each URL entry in the 'url' list
        for url_info in application_blocked.get('url', []):
            # Check if the URL is blocked
            if url_info.get('is_blocked', False):
                # If the URL is blocked, append it to the 'url' list in blocked_apps
                blocked_apps['url'].append(removeprotocals(url_info['url']))

    return blocked_apps

@api.route("/0/export")
class ExportAllResource(Resource):
    @api.doc(model=buckets_export)
    @api.doc(params={"format": "Export format (csv, excel, pdf)",
                     "date": "Date for which to export data (today, yesterday)"})
    def get(self):
        try:
            cache_key = "Sundial"
            cached_credentials = cache_user_credentials(cache_key, "SD_KEYS")
            settings = db_cache.retrieve("settings_cache")

            export_format = request.args.get("format", "csv")
            _day = request.args.get("date", "today")

            if _day not in ["today", "yesterday"]:
                return {"message": "Invalid date parameter"}, 400

            combined_events = []
            if _day == "today":
                day_start = datetime.combine(datetime.now(), time.min)
                day_end = datetime.combine(datetime.now(), time.max)
            else:
                day_start = datetime.combine(datetime.now() - timedelta(days=1), time.min)
                day_end = datetime.combine(datetime.now() - timedelta(days=1), time.max)

            buckets_export = current_app.api.get_dashboard_events(day_start, day_end)

            if 'events' in buckets_export:
                blocked_events = blocked_list()
                combined_events = [event for event in buckets_export['events'] if
                                   not (event.get('app') in blocked_events.get('app', []) or
                                        event.get('url') in blocked_events.get('url', []))]

            df = pd.DataFrame(combined_events)[::-1]

            # Parse timestamp column to datetime
            df["datetime"] = pd.to_datetime(df["timestamp"], utc=True)

            if not df.empty:
                timezone_offset = settings.get('time_zone', '+00:00')
                df["datetime"] = df["datetime"].dt.tz_convert(timezone_offset)

            if _day == "today":
                df = df[df["datetime"].dt.date == datetime.now().date()]
            elif _day == "yesterday":
                df = df[df["datetime"].dt.date == (datetime.now() - timedelta(days=1)).date()]
            df["duration"] = df['duration'].apply(np.ceil)
            df["Time Spent"] = df["duration"].apply(lambda x: format_duration(x))
            df['Application Name'] = df['application_name'].str.capitalize()
            df['Event Data'] = df['title'].astype(str)

            timeformat = settings.get('timeformat', '12')
            if int(timeformat) == 12:
                df["Event Timestamp"] = df["datetime"].dt.strftime('%I:%M:%S %p')
            elif int(timeformat) == 24:
                df["Event Timestamp"] = df["datetime"].dt.strftime('%H:%M:%S')

            if 'id' in df.columns:
                df.drop('id', axis=1, inplace=True)

            df.insert(0, 'SL NO.', range(1, 1 + len(df)))
            df = df[['SL NO.', 'Application Name', 'Time Spent', 'Event Timestamp', 'Event Data']]

            if export_format == "csv":
                return self.create_csv_response(df, cached_credentials)
            elif export_format == "excel":
                return self.create_excel_response(df, cached_credentials)
            elif export_format == "pdf":
                column_widths = {
                    'SL NO.': 50,
                    'Application Name': 150,
                    'Time Spent': 100,
                    'Event Timestamp': 150,
                    'Event Data': 300,
                }

                for column, width in column_widths.items():
                    if column in df.columns:
                        df[column] = df[column].apply(
                            lambda
                                x: f'<div style="width: {width}px; display: inline-block; word-break: break-word;">{x}</div>')

                styled_df_html = df.to_html(index=False, escape=False, classes=['table', 'table-bordered'],
                                            justify='center')
                return self.create_pdf_response(styled_df_html, _day, cached_credentials)
            else:
                return {"message": "Invalid export format"}, 400
        except Exception as e:
            logger.error("An error occurred: %s", e)
            return {"message": "An error occurred during export. Please try again later."}, 500

    def create_csv_response(self, df, user_details):
        """
         Create a response that can be used to export a dataframe as a CSV.

         @param df - The dataframe to export. Must be a : class : ` pandas. DataFrame ` instance.

         @return A : class : ` werkzeug. http. Response ` instance
        """
        csv_buffer = BytesIO()
        df.to_csv(csv_buffer, index=False)
        csv_buffer.seek(0)
        response = make_response(csv_buffer.getvalue())
        response.headers[
            "Content-Disposition"] = f"attachment; filename={user_details['firstname']}_{datetime.now()}.csv"
        response.headers["Content-Type"] = "text/csv"
        return response

    def create_excel_response(self, df, user_details):
        """
         Create an excel response. This is a wrapper around pandas. to_excel to allow us to write a file to the user's browser

         @param df - The dataframe to be exported

         @return A WSGI response with the data in the excel
        """
        excel_buffer = BytesIO()
        with pd.ExcelWriter(excel_buffer, engine='xlsxwriter') as writer:
            df.to_excel(writer, index=False)
        excel_buffer.seek(0)

        response = make_response(excel_buffer.getvalue())
        response.headers[
            "Content-Disposition"] = f"attachment; filename={user_details['firstname']}_{datetime.now()}.xlsx"
        response.headers["Content-Type"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

        return response

    def create_pdf_response(self, df, _day, user_details):
        """
         Create a PDF response. It is used to display Sundial data in the web browser

         @param df - A dataframe containing the Sundial data
         @param _day - The day of the week that the df is in

         @return A string containing the pdf data in the web browser
        """
        """
         Create a PDF response. It is used to display Sudial data in the web browser

         @param df - A dataframe containing the Sundial data
         @param _day - The day of the week that the df
        """
        css = """
            <style type="text/css">
                body {
                    font-family: Cambria, Georgia, "Times New Roman", Times, serif;
                    font-size: 10px; /* Adjust the font size as needed */
                }
                table {
                    width: 100%; /* Adjust the table width as needed */
                    border: 1px solid #000; /* Black border */
                }
                th, td {
                    text-align: center;
                    padding: 5px; /* Adjust cell padding as needed */
                     /* Allow text to wrap within cells */
                }
                th {
                    background-color: #f2f2f2; /* Gray background for table header */
                }
                td {
                    background-color: #fff; /* White background for table cells */
                    -pdf-word-wrap: CJK;
                }
                .header {
                    width: 100%;
                    text-align: center; /* Center logo */
                }
                .header img {
                    width: 200px; /* Adjust as needed */
                }
                .text-container {
                    text-align: left;
                    margin-top: 10px; /* Spacing after the logo */
                }
            </style>
            """

        header = f"""
            <div class='header'>
                <div class='logo-container'>
                <img src="data:image/png;base64,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" alt='Logo'>
                </div>
                <div class="text-container">
                    <p>Name: {user_details['firstname']}</p>
                    <p>Email: {user_details['email']}</p>
                    <p>Date: {date.today() if _day == "today" else date.today() - timedelta(days=1)}</p>
                </div>
            </div>
            """

        styled_html = f"{css}<body>{header}{df}</body>"
        buffer = BytesIO()
        pdf = pisa.CreatePDF(BytesIO(styled_html.encode("UTF-8")), dest=buffer)
        response = make_response(pdf.dest.getvalue())
        response.headers["Content-Type"] = "application/pdf"
        response.headers[
            "Content-Disposition"] = f"attachment; filename={user_details['firstname']}_{datetime.now()}.pdf"
        return response


# TODO: Perhaps we don't need this, could be done with a query argument to /0/export instead
@api.route("/0/buckets/<string:bucket_id>/export")
class BucketExportResource(Resource):
    @api.doc(model=buckets_export)
    @copy_doc(ServerAPI.export_bucket)
    def get(self, bucket_id):
        bucket_export = current_app.api.export_bucket(bucket_id)
        payload = {"buckets": {bucket_export["id"]: bucket_export}}
        response = make_response(json.dumps(payload))
        filename = "sd-bucket-export_{}.json".format(bucket_export["id"])
        response.headers["Content-Disposition"] = "attachment; filename={}".format(
            filename
        )
        return response


@api.route("/0/user_details")
class UserDetails(Resource):
    @copy_doc(ServerAPI.get_user_details)
    def get(self):
        """
         Get user details. This is a view that can be used to retrieve user details from the API.


         @return A dictionary of user details keyed by user id. Example request **. : http Example response **
        """
        user_details = current_app.api.get_user_details()
        return user_details


@api.route("/0/import")
class ImportAllResource(Resource):
    @api.expect(buckets_export)
    @copy_doc(ServerAPI.import_all)
    def post(self):
        """
         Import buckets from json file or POST request. This is a REST API call


         @return 200 if successful 400 if
        """
        # If import comes from a form in th web-ui
        # Upload multiple files to the server.
        if len(request.files) > 0:
            # web-ui form only allows one file, but technically it's possible to
            # upload multiple files at the same time
            # Import all buckets from the request.
            for filename, f in request.files.items():
                buckets = json.loads(f.stream.read())["buckets"]
                current_app.api.import_all(buckets)
        # Normal import from body
        else:
            buckets = request.get_json()["buckets"]
            current_app.api.import_all(buckets)
        return None, 200


# LOGGING
@api.route("/0/settings")
class SaveSettings(Resource):
    @copy_doc(ServerAPI.save_settings)
    @api.doc(security="Bearer")
    def post(self):
        """
        Save settings to the database. This is a POST request to /api/v1/settings.

        @return: 200 if successful, 400 if there is an error.
        """
        # Parse JSON data sent in the request body
        data = request.get_json()
        if data:
            # Extract 'code' and 'value' from the parsed JSON
            code = data.get('code')
            value = data.get('value')
            # Check if both 'code' and 'value' are present
            if code is not None and value is not None:
                # Convert value to JSON string
                value_json = value

                # Save settings to the database
                result = current_app.api.save_settings(code=code, value=value_json)

                # Prepare response dictionary
                result_dict = {
                    "id": result.id,  # Assuming id is the primary key of SettingsModel
                    "code": result.code,
                    "value": value_json  # Use the converted value
                }

                return result_dict, 200  # Return the result dictionary with a 200 status code
            else:
                # Handle the case where 'code' or 'value' is missing in the JSON body
                return {"message": "Both 'code' and 'value' must be provided"}, 400
        else:
            # Handle the case where no JSON is provided
            return {"message": "No settings provided"}, 400


@api.route("/0/getsettings/")
class retrieveSettings(Resource):
    @copy_doc(ServerAPI.get_settings)
    @api.doc(security="Bearer")
    def delete(self):
        """
        Delete settings from the database. This is a DELETE request to /api/v1/settings/{code}.

        @param code: The code associated with the settings to be deleted.
        @return: 200 if successful, 404 if settings not found.
        """
        # Delete settings from the database
        # Assuming current_app.api.delete_settings() is your method to delete settings
        data = request.get_json()
        code = data.get('code')
        result = current_app.api.get_settings(code=code)
        if result:
            return {"message": "Settings deleted successfully", "code": code}, 200
        else:
            return {"message": f"No settings found with code '{code}'"}, 404

@api.route("/0/settings/<string:code>")
class DeleteSettings(Resource):
    @copy_doc(ServerAPI.delete_settings)
    @api.doc(security="Bearer")
    def delete(self, code):
        """
        Delete settings from the database. This is a DELETE request to /api/v1/settings/{code}.

        @param code: The code associated with the settings to be deleted.
        @return: 200 if successful, 404 if settings not found.
        """
        # Delete settings from the database
        # Assuming current_app.api.delete_settings() is your method to delete settings
        result = current_app.api.delete_settings(code=code)
        if result:
            return {"message": "Settings deleted successfully", "code": code}, 200
        else:
            return {"message": f"No settings found with code '{code}'"}, 404



@api.route("/0/getallsettings")
class GetAllSettings(Resource):
    @copy_doc(ServerAPI.retrieve_all_settings)
    @api.doc(security="Bearer")
    def get(self):
        """
        Get settings. This is a GET request to /0/getsettings/{code}.
        """
        settings_dict = db_cache.cache_data("settings_cache")
        if settings_dict is None:
            db_cache.cache_data("settings_cache",current_app.api.retrieve_all_settings())
            settings_dict = db_cache.cache_data("settings_cache")

        return settings_dict


@api.route("/0/getschedule")
class GetSchedule(Resource):
    @copy_doc(ServerAPI.retrieve_all_settings)
    @api.doc(security="Bearer")
    def get(self):
        """
        Get settings. This is a GET request to /0/getsettings/{code}.
        """
        settings_dict = db_cache.cache_data("settings_cache")
        if settings_dict is None:
            db_cache.cache_data("settings_cache",current_app.api.retrieve_all_settings())
            settings_dict = db_cache.cache_data("settings_cache")
        return json.loads(settings_dict["weekdays_schedule"]),200


@api.route("/0/applicationsdetails")
class SaveApplicationDetails(Resource):
    @api.doc(security="Bearer")
    @copy_doc(ServerAPI.save_application_details)
    def post(self):
        """
        Save application details to the database. This is a POST request to /api/v0/applications.

        @return: 200 if successful, 400 if there is an error.
        """
        # Parse JSON data sent in the request body
        data = request.get_json()
        if data:
            # Extract necessary fields from the parsed JSON
            name = data.get('name')
            url = data.get('url')
            type = data.get('type')
            alias = data.get('alias')
            is_blocked = data.get('is_blocked', False)
            is_ignore_idle_time = data.get('is_ignore_idle_time', False)
            color = data.get('color')

            # Check if the essential field 'name' is present
            # Construct a dictionary with application details
            application_details = {
                "name": name,
                "url": url,
                "type": type,
                "alias": alias,
                "is_blocked": is_blocked,
                "is_ignore_idle_time": is_ignore_idle_time,
                "color": color
            }

            # Remove None values to avoid overwriting with None in the database
            application_details = {k: v for k, v in application_details.items() if v is not None}

            # Save application details to the database
            # Assuming current_app.api.save_application_details() is your method to save application details
            result = current_app.api.save_application_details(application_details)
            if result is not None:
                return {"message": "Application details saved successfully",
                        "result": result.json()}, 200  # Use .json() method to serialize the result
            else:
                return {"message": "Error saving application details"}, 500
        else:
            # Handle the case where no JSON is provided
            return {"message": "No application details provided"}, 400


@api.route("/0/getapplicationdetails")
class getapplicationdetails(Resource):
    @copy_doc(ServerAPI.get_appication_details)
    @api.doc(security="Bearer")
    def get(self):
        """
         Get settings. This is a GET request to / api / v1 /
        """
        return current_app.api.get_appication_details()


@api.route("/0/deleteapplication/<int:application_id>")
class DeleteApplicationDetails(Resource):
    @copy_doc(ServerAPI.delete_application_details)
    @api.doc(security="Bearer")
    def delete(self, application_id):
        """
        Delete application details. This is a DELETE request to /api/v1/deleteapplication/{application_name}
        """
        delete_app = current_app.api.delete_application_details(application_id)
        if delete_app:
            # Convert the ApplicationModel instance to a dictionary
            delete_app_dict = {
                "name": delete_app.name,
                "type": delete_app.type,
                "alias": delete_app.alias,
                "is_blocked": delete_app.is_blocked,
                "is_ignore_idle_time": delete_app.is_ignore_idle_time,
                "color": delete_app.color
            }
            return {"message": "Application details deleted successfully", "result": delete_app_dict}, 200
        else:
            return {"message": "Error deleting application details"}, 500


@api.route("/0/log")
class LogResource(Resource):
    @copy_doc(ServerAPI.get_log)
    def get(self):
        """
         Get logs. This endpoint is used to retrieve log entries. The request must be made by the user to make an HTTP GET request.


         @return 200 OK with log ( dict ) 400 Bad Request if log does not
        """
        return current_app.api.get_log(), 200


@api.route('/0/start/')
class StartModule(Resource):
    @api.doc(security="Bearer")
    @api.doc(params={"module": "Module Name", })
    def get(self):
        """
         Start modules on the server. This will return a message to the client indicating that the module has started.


         @return JSON with the message that was sent to the client
        """
        module_name = request.args.get("module")
        message = manager.start_modules(module_name)
        return jsonify({"message": message})


@api.route('/0/stop/')
class StopModule(Resource):
    @api.doc(security="Bearer")
    @api.doc(params={"module": "Module Name", })
    def get(self):
        """
         Stop a module by name. This is a GET request to / v1 / modules / : id


         @return JSON with message to
        """
        module_name = request.args.get("module")
        message = manager.stop_modules(module_name)
        return jsonify({"message": message})


@api.route('/0/status')
class Status(Resource):
    @api.doc(security="Bearer")
    def get(self):
        """
         Get list of modules. This is a GET request to / modules. The response is a JSON object with a list of modules.


         @return a JSON object with a list of modules in the
        """
        modules = manager.status()

        return jsonify(modules)


@api.route('/0/idletime')
class idletime(Resource):
    @api.doc(security="Bearer")
    def get(self):
        """
         Get list of modules. This is a GET request to / modules. The response is a JSON object with a list of modules.


         @return a JSON object with a list of modules in the
        """
        module = manager.module_status("sd-watcher-afk")
        if module["is_alive"]:
            manager.stop("sd-watcher-afk")
            message = "idle time has stoppped"
            state = False
        else:
            manager.start("sd-watcher-afk")
            message = "idle time has started"
            state = True
        current_app.api.save_settings("idle_time",state)
        return {"message": message}, 200


@api.route('/0/credentials')
class User(Resource):

    def get(self):
        """
         Get information about the user. This is a GET request to the Sundial API.


         @return JSON with firstname lastname and email or False if not
        """
        cache_key = "Sundial"
        cached_credentials = cache_user_credentials(cache_key, "SD_KEYS")
        user_key = cached_credentials.get("encrypted_db_key") if cached_credentials else None
        # Returns a JSON response with the user s credentials.
        if user_key is None:
            return False, 404
        else:
            return jsonify(
                {"firstName": cached_credentials.get("firstname"), "lastName": cached_credentials.get("lastname"),
                 "email": cached_credentials.get("email")})


@api.route("/0/dashboard/events")

class DashboardResource(Resource):
    def get(self):
        """
        Get dashboard events. GET /api/dashboards/[id]?start=YYYYMMDD&end=YYYYMMDD
        @return 200 on success, 400 if not found, 500 if other
        """
        args = request.args
        start = iso8601.parse_date(args.get("start")) if "start" in args else None
        end = iso8601.parse_date(args.get("end")) if "end" in args else None

        blocked_apps = blocked_list()  # Assuming this function returns a list of blocked events
        events = current_app.api.get_dashboard_events(start=start, end=end)
        if events:
            for i in range(len(events['events']) - 1, -1, -1):
                event = events['events'][i]
                # if "url" in event['data'].keys() and event['data']['url'] and event['data'] ['url'].replace("https://","").replace("http://", "").replace("www.", "") in blocked_apps['url']:
                # print("blocked url",blocked_apps['url'])
                if event['data']['app'] in blocked_apps['app']:
                    del events['events'][i]
                elif removeprotocals(event['url']) in blocked_apps['url']:
                    del events['events'][i]
        return events, 200


@api.route("/0/dashboard/most_used_apps")
class MostUsedAppsResource(Resource):
    def get(self):
        """
         Get most used apps. This will return a list of apps that have been used in the last 24 hours.


         @return 200 OK if everything worked else 500 Internal Server Error
        """
        args = request.args
        start_time =  parse(args["start"])
        end_time = parse(args["end"])
        # start = iso8601.parse_date(start_time) if "start" in args else None
        # end = iso8601.parse_date(end_time) if "end" in args else None

        blocked_apps = blocked_list()
        events = current_app.api.get_most_used_apps(
            start=start_time, end=end_time
        )
        if events:
            for i in range(len(events['most_used_apps']) - 1, -1, -1):
                app_data = events['most_used_apps'][i]
                if "url" in app_data.keys() and app_data['url'] in blocked_apps['url']:
                        del events['most_used_apps'][i]

        return events, 200


@api.route("/0/applicationlist")
class ApplicationListResource(Resource):
    @copy_doc(ServerAPI.application_list)
    def get(self):
        applications = current_app.api.application_list()
        return applications, 200

@api.route("/0/sync_server")
class SyncServer(Resource):
    def get(self):
        try:
            status = current_app.api.sync_events_to_ralvie()

            if status['status'] == "success":
                return {"message": "Data has been synced successfully"}, 200
            elif status['status'] == "Synced_already" or status['status'] == "no_event_ids":
                return {"message": "Data has been synced already"}, 201
            else:
                return {"message": "Data has not been synced"}, 500
        except Exception as e:
            # Log the error and return a 500 status code
            current_app.logger.error("Error occurred during sync_server: %s", e)
            return {"message": "Internal server error"}, 500


@api.route("/0/launchOnStart")
class LaunchOnStart(Resource):
    def post(self):
        status = request.json.get("status")
        if sys.platform == "darwin":

            if status is None:
                return {"error": "Status is required in the request body."}, 400

            if status:
                launch_app()
                current_app.api.save_settings("launch", status)
                return {"message": "Launch on start enabled."}, 200
            else:
                delete_launch_app()
                current_app.api.save_settings("launch", status)
                return {"message": "Launch on start disabled."}, 200
        elif sys.platform == "win32":
            if status is None:
                return {"error": "Status is required in the request body."}, 400

            if status:
                set_autostart_registry(autostart=True)
                current_app.api.save_settings("launch", status)
                return {"message": "Launch on start enabled."}, 200
            else:
                set_autostart_registry(autostart=False)
                current_app.api.save_settings("launch", status)
                return {"message": "Launch on start disabled."}, 200

# Refresh token
@api.route("/0/ralvie/refresh_token")
class RalvieTokenRefreshResource(Resource):
    def put(self):
        """
         Refresh token. This is the endpoint for refreshing the access token.


         @return A JSON with the result of the authentication and user
        """
        # If the internet is not connected return a 200 error message.
        if not is_internet_connected():
            return jsonify({"message": "Please connect to the internet and try again."}), 200

        data = request.get_json()

        auth_result = current_app.api.refresh_token(data)

        # Returns a JSON response with the user credentials.
        if auth_result.status_code == 200 and json.loads(auth_result.text)["code"] == 'UASI0011':
            token = json.loads(auth_result.text)["data"]["access_token"]
            refresh_token = json.loads(auth_result.text)["data"]["refresh_token"]


            return {"code": "UASI0011", "message": json.loads(auth_result.text)["message"],
                    "data": {"access_token": 'Bearer ' + token,"refresh_token": refresh_token}}, 200
        else:
            return {"code": json.loads(auth_result.text)["code"], "message": json.loads(auth_result.text)["message"],
                    "data": json.loads(auth_result.text)["data"]}, 200

@api.route("/0/user/profile")
class UpdateUserProfile(Resource):

    def put(self):
        # Get the URL from the request
        access_token = request.form.get('access_token')

        # Get the file from the request
        file = request.files['file']

        return current_app.api.update_user_profile(access_token, file)

@api.route("/0/user/<string:token>")
class UserDetailsById(Resource):
    @copy_doc(ServerAPI.get_user_by_id)
    def get(self, token):
        """
         Get user details. This is a view that can be used to retrieve user details from the API.

         @param token: The token associated with the user.
         @return A dictionary of user details keyed by user id. Example request **. : http Example response **
        """
        return current_app.api.get_user_by_id(token)

@api.route("/0/user/profile_photo/<string:token>")
class DeleteUserProfilePhoto(Resource):
    @copy_doc(ServerAPI.delete_user_profile_photo)
    def delete(self, token):
        """
         Delete user profile phot.

         @param token: The token associated with the user.
         @return Success response or failure response. Example request **. : http Example response **
        """
        return current_app.api.delete_user_profile_photo(token)




