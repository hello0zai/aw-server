import logging
import os
from datetime import datetime, timedelta
from typing import Dict, List
import webbrowser
import sd_datastore
import flask.json.provider
from sd_datastore import Datastore
from flask import (
    Blueprint,
    Flask,
    current_app,
    send_from_directory,
)
from flask_cors import CORS

from . import rest
from .api import ServerAPI
from .custom_static import get_custom_static_blueprint
from .log import FlaskLogHandler

logger = logging.getLogger(__name__)

app_folder = os.path.dirname(os.path.abspath(__file__))
static_folder = os.path.join(app_folder, "static")

root = Blueprint("root", __name__, url_prefix="/")


class AWFlask(Flask):
    def __init__(
        self,
        host: str,
        testing: bool,
        storage_method=None,
        cors_origins=[],
        custom_static=dict(),
        static_folder=static_folder,
        static_url_path="",
    ):
        """
         Initialize server and register blueprints. This is called by : meth : ` Flask. __init__ ` but can be called multiple times to re - initialize the server at the same time

         @param host - host to connect to e. g.
         @param testing - if True tests will be run in production mode
         @param storage_method - name of method used to store data
         @param cors_origins - list of origins for CORS headers
         @param custom_static - dictionary of custom static data to be used for static files
         @param static_folder - path to folder where static files are stored
         @param static_url_path - path to url where static files are
        """
        name = "sd-server"
        self.json_provider_class = CustomJSONProvider
        # only prettyprint JSON if testing (due to perf)
        self.json_provider_class.compact = not testing

        # Initialize Flask
        Flask.__init__(
            self,
            name,
            static_folder=static_folder,
            static_url_path=static_url_path,
        )
        self.config["HOST"] = host  # needed for host-header check
        with self.app_context():
            _config_cors(cors_origins, testing)

        # Initialize datastore and API
        # Get the storage method for the datastore.
        if storage_method is None:
            storage_method = sd_datastore.get_storage_methods()["memory"]
        db = Datastore(storage_method, testing=testing)
        self.api = ServerAPI(db=db, testing=testing)
        self.api.ralvie_server_queue.start()
        self.register_blueprint(root)
        self.register_blueprint(rest.blueprint)
        # self.register_blueprint(get_custom_static_blueprint(custom_static))


class CustomJSONProvider(flask.json.provider.DefaultJSONProvider):
    # encoding/decoding of datetime as iso8601 strings
    # encoding of timedelta as second floats
    def default(self, obj, *args, **kwargs):
        """
         Convert datetime to ISO format. This is a workaround for Python 2. 7 and earlier which don't support ISO formatting.

         @param obj - Object to convert to string. Can be any type but not all objects are supported.

         @return String representation of the object or None if it can't be converted to a string ( in which case the object is returned as - is
        """
        try:
            # Return the ISO 8601 format of the object.
            if isinstance(obj, datetime):
                return obj.isoformat()
            # Return the total number of seconds of the object.
            if isinstance(obj, timedelta):
                return obj.total_seconds()
        except TypeError:
            pass
        return super().default(obj)


@root.route("/")
def static_root():
    """
     Serve static root page. This is used to serve static root page for application. You can use it in templates or any other way that you want to serve static root page.


     @return Response from server or None if request is not responded to by client or server side error ( 404
    """
    return current_app.send_static_file("index.html")

@root.route("/pages/<path:path>")
def static_home_root(path):
    """
     Serve static home root. This is the root of the application's static files. By default it is the index. html page

     @param path - path to the static root

     @return response to the static root page with no Content - Type header set to application / x - www - form - urlencoded
    """
    return current_app.send_static_file("index.html")


@root.route("/css/<path:path>")
def static_css(path):
    """
     Send static CSS to client. This is a shortcut for : func : ` send_from_directory `

     @param path - Path to css file.

     @return HTML response from server or None if error occured ( 404 not found ). Example usage :. from werkzeug import static_
    """
    return send_from_directory(static_folder + "/css", path)


@root.route("/js/<path:path>")
def static_js(path):
    """
     Send static javascript to client. This is a shortcut for : func : ` send_from_directory `

     @param path - Path to file relative to static folder

     @return String of javascript to be sent to client Example :. from werkzeug. ext. http import static_
    """
    return send_from_directory(static_folder + "/js", path)


def _config_cors(cors_origins: List[str], testing: bool):
    """
     Configure CORS to allow cross - origin requests. This is a helper function for _config_exameters which can be used to add additional origins to the CORS configuration

     @param cors_origins - List of origins to allow
     @param testing - If True will use HTTP and HTTPS instead of
    """
    # This method is called by the CLI to check if CORS origins are specified through config or CLI arguments.
    if cors_origins:
        logger.warning(
            "Running with additional allowed CORS origins specified through config "
            "or CLI argument (could be a security risk): {}".format(cors_origins)
        )

    # Use this method to add CORS origins to the CORS_origins list.
    if testing:
        # Used for development of sd-webui
        cors_origins.append("http://127.0.0.1:27180/*")

    # TODO: This could probably be more specific
    #       See https://github.com/ActivityWatch/sd-server/pull/43#issuecomment-386888769
    cors_origins.append("moz-extension://*")

    # See: https://flask-cors.readthedocs.org/en/latest/
    CORS(current_app, resources={r"/api/*": {"origins": cors_origins}})


# Only to be called from sd_server.main function!
def _start(
    storage_method,
    host: str,
    port: int,
    testing: bool = False,
    cors_origins: List[str] = [],
    custom_static: Dict[str, str] = dict(),
):
    """
     Start the Flask application. This is a wrapper around AWFlask to allow us to run in a subprocess

     @param storage_method - Storage method to use for the app
     @param host - Host to connect to e. g. " localhost "
     @param port - Port to connect to e. g. 802. 151
     @param testing - If True use test mode instead of production
     @param cors_origins - List of origins to allow cross - origin requests
     @param custom_static - Dict of custom static variables to pass to
    """
    app = AWFlask(
        host,
        testing=testing,
        storage_method=storage_method,
        cors_origins=cors_origins,
        custom_static=custom_static,
    )
    webbrowser.open("http://"+ host+ ":" + str(port))
    try:
        app.run(
            debug=testing,
            host=host,
            port=port,
            request_handler=FlaskLogHandler,
            use_reloader=False,
            threaded=True,
        )
    except OSError as e:
        logger.exception(e)
        raise e
