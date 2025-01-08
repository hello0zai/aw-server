import sys
import getpass
import json
import traceback
from functools import wraps
from threading import Lock
from typing import Dict
from datetime import datetime, timedelta, date, time

import iso8601
import pytz
import jwt
from flask_restx import Api, Resource, fields
from flask import (
    Blueprint,
    current_app,
    jsonify,
    make_response,
    request,
)

from sd_core.launch_start import delete_launch_app, launch_app, check_startup_status, set_autostart_registry
from sd_core.util import authenticate, is_internet_connected, reset_user
from sd_core import schema, db_cache
from sd_core.models import Event
from sd_core.cache import *
from sd_query.exceptions import QueryException
from . import logger
from .api import ServerAPI
from .exceptions import BadRequest, Unauthorized
from sd_qt.manager import Manager

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
    Protects against DNS rebinding attacks (see https://github.com/ActivityWatch/activitywatch/security/advisories/GHSA-v9fg-6g9j-h4x4)

    Some discussion in Syncthing how they do it: https://github.com/syncthing/syncthing/issues/4819
    """

    @wraps(f)
    def decorator(*args, **kwargs):
        server_host = current_app.config["HOST"]
        req_host = request.headers.get("host", None)
        if server_host == "0.0.0.0":
            logger.warning(
                "Server is listening on 0.0.0.0, host header check is disabled (potential security issue)."
            )
        elif req_host is None:
            return {"message": "host header is missing"}, 400
        else:
            if req_host.split(":")[0] not in ["localhost", "127.0.0.1", server_host]:
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
api = Api(blueprint, doc="/",
          decorators=[host_header_check], authorizations=authorizations)

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
        cached_credentials = cache_user_credentials("Sundial")
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

                    companyResult = current_app.api.create_company(
                        companyPayload, 'Bearer ' + token)

                    # This method is called when the user is created
                    if companyResult.status_code == 200 and json.loads(companyResult.text)["code"] == 'UASI0006':
                        current_app.api.get_user_credentials(
                            id, 'Bearer ' + token)
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
        cached_credentials = cache_user_credentials("Sundial")
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
        cached_credentials = cache_user_credentials("Sundial")
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
        refresh_token = ""
        # Check Internet Connectivity
        response_data = {}
        # If the internet is not connected return a 200 error message.
        if not is_internet_connected():
            return jsonify({"message": "Please connect to the internet and try again."}), 200

        # Parse Request Data
        data = request.get_json()
        user_name = data.get('userName')
        password = data.get('password')
        companyId = data.get('companyId', None)
        print(user_name, password, companyId)
        user_id = None

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
            cached_credentials = cache_user_credentials("Sundial")
            token = json.loads(auth_result.text)["data"]["access_token"]
            # Get the User Key
            user_key = cached_credentials.get(
                "encrypted_db_key") if cached_credentials else None

            token = json.loads(auth_result.text)["data"]["access_token"]
            refresh_token = json.loads(auth_result.text)[
                "data"]["refresh_token"]
            # store_credentials(cache_key, SD_KEYS)
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
                "email": cache_user_credentials("Sundial").get("email"),
                "phone": cache_user_credentials("Sundial").get("phone"),
            }
            encoded_jwt = jwt.encode(payload, cache_user_credentials("Sundial").get("user_key"),
                                     algorithm="HS256")

            # Response
            response_data['code'] = "UASI0011",
            response_data["message"] = json.loads(auth_result.text)["message"],
            response_data['companyId'] = companyId,
            response_data["data"]: {"token": "Bearer " + encoded_jwt}
            return {"code": "UASI0011", "message": json.loads(auth_result.text)["message"], "companyId": companyId,
                    "data": {"token": "Bearer " + encoded_jwt, "access_token": "Bearer " + token, "refresh_token": refresh_token}, "userId": user_id}, 200
        else:
            return {"code": json.loads(auth_result.text)["code"], "message": json.loads(auth_result.text)["message"],
                    "data": json.loads(auth_result.text)["data"], "userId": user_id}, 200


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

        events = current_app.api.get_eventcount(
            bucket_id, start=start, end=end)
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

def time_in_range(start, end, x):
    """Return true if x is in the range [start, end]"""
    if start <= end:
        return start <= x <= end
    else:
        return start <= x or x <= end


@api.route("/0/buckets/<string:bucket_id>/heartbeat")
class HeartbeatResource(Resource):
    def __init__(self, *args, **kwargs):
        self.lock = Lock()
        super().__init__(*args, **kwargs)

    @api.expect(event, validate=True)
    @api.param("pulsetime", "Largest time window allowed between heartbeats for them to merge")
    @copy_doc(ServerAPI.heartbeat)
    def post(self, bucket_id):
        heartbeat_data = request.get_json()

        if not heartbeat_data['data'].get('title'):
            heartbeat_data['data']['title'] = heartbeat_data['data'].get('app', '')

        if heartbeat_data['data'].get('app') == 'ApplicationFrameHost.exe':
            heartbeat_data['data']['app'] = f"{heartbeat_data['data']['title']}.exe"

        # Retrieve settings
        settings = db_cache.retrieve("settings_cache")
        if not settings:
            settings = current_app.api.retrieve_all_settings()
            db_cache.store("settings_cache", settings)

        # Extract the weekdays schedule
        weekdays_schedule = settings.get("weekdays_schedule", {})
        current_time = datetime.now()
        day_name = current_time.strftime("%A").lower()
        schedule = settings.get("schedule", False)

        # Check if the current day is scheduled (True)
        if not weekdays_schedule.get(day_name.capitalize(), False) and schedule:
            print(f"Skipping data capture for {day_name} - not scheduled.")
            return {"message": f"Skipping data capture for {day_name}."}, 200

        # Time range check for scheduling
        start_time_str = weekdays_schedule.get("starttime")
        end_time_str = weekdays_schedule.get("endtime")

        if start_time_str and end_time_str and schedule:
            try:
                time_format = "%H:%M:%S"
                local_start_time = datetime.strptime(f"{current_time.date()} {start_time_str}",
                                                     f"%Y-%m-%d {time_format}")
                local_end_time = datetime.strptime(f"{current_time.date()} {end_time_str}", f"%Y-%m-%d {time_format}")
                print(local_start_time,local_end_time,current_time)

                # Check if the current time is within the scheduled range
                if not (local_start_time <= current_time < local_end_time):
                    print(f"Skipping data capture due to time restriction. Current time: {current_time}, "
                          f"Scheduled start: {local_start_time}, Scheduled end: {local_end_time}.")
                    return {"message": "Skipping data capture due to time restriction."}, 200

            except (ValueError, json.JSONDecodeError) as e:
                logger.error(f"Error parsing schedule: {e}")
                return {"message": "Schedule parsing error."}, 500

        # Proceed with heartbeat processing
        heartbeat = Event(**heartbeat_data)
        cached_credentials = cache_user_credentials("Sundial")

        if cached_credentials is None:
            return {"message": "No cached credentials."}, 400

        try:
            pulsetime = float(request.args.get("pulsetime"))
        except (ValueError, TypeError):
            return {"message": "Missing or invalid required parameter 'pulsetime'"}, 400

        if not self.lock.acquire(timeout=1):
            logger.warning("Heartbeat lock could not be acquired within a reasonable time.")
            return {"message": "Failed to acquire heartbeat lock."}, 500

        try:
            event = current_app.api.heartbeat(bucket_id, heartbeat, pulsetime)
            if event:
                return event.to_json_dict(), 200
            else:
                return {"message": "Heartbeat failed."}, 500
        finally:
            self.lock.release()


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
        db_cache.store(application_cache_key,
                       current_app.api.application_list())

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
                result = current_app.api.save_settings(
                    code=code, value=value_json)

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
            db_cache.cache_data(
                "settings_cache", current_app.api.retrieve_all_settings())
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
            db_cache.cache_data(
                "settings_cache", current_app.api.retrieve_all_settings())
            settings_dict = db_cache.cache_data("settings_cache")
        return json.loads(settings_dict["weekdays_schedule"]), 200


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
            application_details = {
                k: v for k, v in application_details.items() if v is not None}

            # Save application details to the database
            # Assuming current_app.api.save_application_details() is your method to save application details
            result = current_app.api.save_application_details(
                application_details)
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
class Idletime(Resource):
    @api.doc(security="Bearer")
    def get(self):
        """
        Manage the idle time state by starting or stopping the 'sd-watcher-afk' module.

        The 'status' query parameter controls whether the module is started or stopped:
        - If 'status' is 'start', the module is started.
        - If 'status' is 'stop', the module is stopped.

        @return a JSON object with a message indicating the new state.
        """

        try:
            module = manager.module_status("sd-watcher-afk")
            status = request.args.get("status")

            if module is None or "is_alive" not in module:
                return {"message": "Module status could not be retrieved"}, 500
            state = False
            # Check the status argument and start/stop the module accordingly
            if status == "start":
                if not module["is_alive"]:
                    manager.start("sd-watcher-afk")
                    message = "Idle time has started"
                    state = True
                else:
                    message = "Idle time is already running"
                    state = True
            elif status == "stop":
                if module["is_alive"]:
                    manager.stop("sd-watcher-afk")
                    message = "Idle time has stopped"
                    state = False
                else:
                    message = "Idle time is already stopped"
                    state = False
            else:
                return {"message": "Invalid status parameter. Use 'start' or 'stop'."}, 400

            # Save the new idle time state in the settings
            current_app.api.save_settings("idle_time", state)
            return {"message": message}, 200

        except Exception as e:
            logger.error(f"Error handling idle time: {str(e)}")
            return {"message": "An error occurred while managing idle time."}, 500



@api.route('/0/credentials')
class User(Resource):

    def get(self):
        """
         Get information about the user. This is a GET request to the Sundial API.


         @return JSON with firstname lastname and email or False if not
        """
        cache_key = "Sundial"
        cached_credentials = cache_user_credentials("Sundial")
        user_key = cached_credentials.get(
            "encrypted_db_key") if cached_credentials else None
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
        start = iso8601.parse_date(
            args.get("start")) if "start" in args else None
        end = iso8601.parse_date(args.get("end")) if "end" in args else None

        # Assuming this function returns a list of blocked events
        blocked_apps = blocked_list()
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
        start_time = parse(args["start"])
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

            app_sync_status = current_app.api.sync_application_to_ralvie()

            print(app_sync_status)

            if status['status'] == "success":
                return {"message": "Data has been synced successfully"}, 200
            elif status['status'] == "Synced_already" or status['status'] == "no_event_ids":
                return {"message": "Data has been synced already"}, 201
            else:
                return {"message": "Data has not been synced"}, 500
        except Exception as e:
            # Log the error and return a 500 status code
            current_app.logger.error(
                "Error occurred during sync_server: %s", e)
            return {"message": "Internal server error"}, 500


@api.route("/0/launchOnStart")
class LaunchOnStart(Resource):
    @api.doc(security="Bearer")
    def get(self):
        status = request.args.get("status", type=str)  # Expecting status as a query parameter

        if status is None:
            return {"error": "Status is required in the request query."}, 400

        # Convert status to boolean
        status = status.lower() in ["start"]

        if sys.platform == "darwin":
            if status:
                launch_app()  # Ensure this function is defined
                state = True
                current_app.api.save_settings("launch", state)
                return {"message": "Launch on start enabled."}, 200
            else:
                state = False
                delete_launch_app()  # Ensure this function is defined
                current_app.api.save_settings("launch", state)
                return {"message": "Launch on start disabled."}, 200

        elif sys.platform == "win32":
            if status:
                state = True
                set_autostart_registry(autostart=True)  # Ensure this function is defined
                current_app.api.save_settings("launch", state)
                return {"message": "Launch on start enabled."}, 200
            else:
                state = False
                set_autostart_registry(autostart=False)  # Ensure this function is defined
                current_app.api.save_settings("launch", state)
                return {"message": "Launch on start disabled."}, 200

        else:
            return {"error": "Unsupported platform."}, 400  # Handle unsupported platforms

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
            refresh_token = json.loads(auth_result.text)[
                "data"]["refresh_token"]

            return {"code": "UASI0011", "message": json.loads(auth_result.text)["message"],
                    "data": {"access_token": 'Bearer ' + token, "refresh_token": refresh_token}}, 200
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


@api.route("/0/init_db")
class initdb(Resource):
    def get(self):
        init_db = current_app.api.init_db()
        if not init_db:
            print("Error")
        else:
            print("Success")


@api.route("/0/server_status")
class server_status(Resource):
    def get(self):
        return 200
