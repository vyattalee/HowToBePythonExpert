import sys, logging

def use_logging(func):

    def wrapper():
        logging.warning("%s is running" % func.__name__)
        return func()
    return wrapper

@use_logging
def foo():
    print("i am foo")

foo()

from functools import wraps
def logged(func):
    @wraps(func)
    def with_logging(*args, **kwargs):
        print (func.__name__)      # 输出 'f'
        print (func.__doc__)      # 输出 'does some math'
        return func(*args, **kwargs)
    return with_logging

@logged
def f(x):
   """does some math"""
   return x + x * x


print (f(4))