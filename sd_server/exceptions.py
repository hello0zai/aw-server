import werkzeug.exceptions


class BadRequest(werkzeug.exceptions.BadRequest):
    def __init__(self, type: str, message: str) -> None:
        """
         Initializes the exception with the given message. This is the constructor for the exception class. It should be called in the __init__ method of the class.
         
         @param type - The type of the exception. This is used to determine the error code that will be returned when the exception is raised.
         @param message - The message to be displayed to the user.
         
         @return The exception that was raised or None if there was no exception to be raised for the given type and
        """
        super().__init__(message)
        self.type = type


class NotFound(werkzeug.exceptions.NotFound):
    def __init__(self, type: str, message: str) -> None:
        """
         Initializes the exception with the given message. This is the constructor for the exception class. It should be called in the __init__ method of the class.
         
         @param type - The type of the exception. This is used to determine the error code that will be returned when the exception is raised.
         @param message - The message to be displayed to the user.
         
         @return The exception that was raised or None if there was no exception to be raised for the given type and
        """
        super().__init__(message)
        self.type = type


class Unauthorized(werkzeug.exceptions.Unauthorized):
    def __init__(self, type: str, message: str) -> None:
        """
         Initializes the exception with the given message. This is the constructor for the exception class. It should be called in the __init__ method of the class.
         
         @param type - The type of the exception. This is used to determine the error code that will be returned when the exception is raised.
         @param message - The message to be displayed to the user.
         
         @return The exception that was raised or None if there was no exception to be raised for the given type and
        """
        super().__init__(message)
        self.type = type
