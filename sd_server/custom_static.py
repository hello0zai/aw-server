"""
Contains endpoints, as well as utility functions for custom static content.

NOTE: Experimental, not (yet) implemented in sd-server-rust.

Idea: Allow custom watchers to extend the Web UI and to write custom visualizations completely independently and free.

Usage for the watcher developer:
- You can use Vanilla JavaScript, Vue, React, ... as long as you have static content at the end.

- Register your watcher visualization in the config:

[server.custom_static]
sd-watcher-example=/home/user/path/to/static_dir/

- Your custom static content automatically gets the data for the requested time span as GET parameter called "data".
Another parameter called "view" can be used if you want to create multiple visualizations for a single watcher.

- You can show your custom visualizations in the official Activity Watch UI using the "Custom Watcher View"
  See https://github.com/ActivityWatch/activitywatch/issues/453#issuecomment-910567848

"""

from flask import (
    Blueprint,
    escape,
    jsonify,
    send_from_directory,
)


def get_custom_static_blueprint(custom_static_directories):
    """
     Creates and returns a blueprint to serve custom static files. This is useful for creating a blueprint that allows you to add a custom static file to your static files.
     
     @param custom_static_directories - Dictionary of paths to directories that contain static files.
     
     @return A : class : ` Blueprint ` that can be used to serve custom static files from your static directory
    """
    custom_static_blueprint = Blueprint("custom_static", __name__, url_prefix="/")

    @custom_static_blueprint.route("pages/")
    def custom_static_supported_pages():
        """
         Serves a list of all pages that are supported by the static watcher. This is useful for debugging and to see which pages are supported by the static watcher.
         
         
         @return JSON with a list of supported pages in the format { " page " : " supported_pages "
        """
        """Serves a list of all watchers that are supported / were registered successfully"""
        return jsonify(list(custom_static_directories.keys()))

    @custom_static_blueprint.route(
        "pages/<string:name>/", defaults={"path": "index.html"}
    )
    @custom_static_blueprint.route("pages/<string:name>/<path:path>")
    def custom_static_pages(name: str, path: str):
        """
         Serves the custom static pages. This is a wrapper around : func : ` send_from_directory ` to allow the user to add a custom static directory to the watch list.
         
         @param name - The name of the directory that contains the static content.
         @param path - The path to the static file. It must be a directory with a name matching the name of the directory you want to watch.
         
         @return A response that contains the static file and status code as well as the url to the static file if it was found
        """
        """Serves the custom static content"""

        # Send a static content to the watcher.
        if name in custom_static_directories:
            return send_from_directory(custom_static_directories[name], path)
        else:
            return (
                f"Static content: {escape(path)} of watcher: {escape(name)} not found!",
                404,
            )

    return custom_static_blueprint
