from functools import wraps

from flask import session, redirect



def login_required(func):


    @wraps(func)
    def wrapper(*args, **kwargs):


        if "username" not in session:

            return redirect("/login")


        return func(*args, **kwargs)


    return wrapper