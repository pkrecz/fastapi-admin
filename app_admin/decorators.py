from functools import wraps
from .repository import repo_functions


def permission_required(required_permission: str):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            repo_functions.check_permission(db = kwargs["db"],
                                            user = kwargs["current_user"],
                                            required_permission = required_permission)            
            return await func(*args, **kwargs)
        return wrapper
    return decorator
