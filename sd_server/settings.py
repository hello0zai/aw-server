import json
from pathlib import Path

from sd_core.dirs import get_config_dir


class Settings:
    def __init__(self, testing: bool):
        """
         Initialize the settings. json file. This is called by __init__ and should not be called directly
         
         @param testing - True if we are testing
        """
        filename = "settings.json" if not testing else "settings-testing.json"
        self.config_file = Path(get_config_dir("sd-server")) / filename
        self.load()

    def __getitem__(self, key):
        """
         Return the value associated with the key. This is the same as : meth : ` get ` except it doesn't raise KeyError if the key is not found
         
         @param key - The key to look up
         
         @return The value associated with the key or None if not found. >>> mydict. __getitem__ ('key')
        """
        return self.get(key)

    def __setitem__(self, key, value):
        """
         Sets the value associated with the key. This is the same as : meth : ` set ` except that it does not raise an exception if the key doesn't exist
         
         @param key - The key to set.
         @param value - The value to set. It must be serializable to JSON.
         
         @return True if the value was set False otherwise. >>> client. __setitem__ ('key'value ) Traceback ( most recent call last ) : TypeError : key is not
        """
        return self.set(key, value)

    def load(self):
        """
         Load configuration from file if it exists otherwise empty dictionary is stored in self. data. This is called after config has been
        """
        # Load the data from the config file
        if self.config_file.exists():
            with open(self.config_file) as f:
                self.data = json.load(f)
        else:
            self.data = {}

    def save(self):
        """
         Save config to file. This is called by __init__ and should not be called directly by user
        """
        with open(self.config_file, "w") as f:
            json.dump(self.data, f, indent=4)

    def get(self, key: str, default=None):
        """
         Get value by key. If key is empty return self. data. This is useful for debugging and to avoid having to re - read data in case it is changed after an exception is raised
         
         @param key - Key to get value for
         @param default - Default value to return if key is not found
         
         @return Value for key or default if key is not found in self. data or key is not in self
        """
        # Returns the data for this key.
        if not key:
            return self.data
        return self.data.get(key, default)

    def set(self, key, value):
        """
         Set or remove a key / value pair. If value is None delete the key from the data dictionary
         
         @param key - key to set or remove
         @param value - value to set or None to remove the key
        """
        # Set the value of a key in the data.
        if value:
            self.data[key] = value
        else:
            # Remove a key from the data.
            if key in self.data:
                del self.data[key]
        self.save()
