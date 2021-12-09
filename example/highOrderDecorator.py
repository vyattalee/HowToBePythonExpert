def ntimes(n):
    def inner(f):
        def wrapper(*args, **kwargs):
            for _ in range(n):
                print('running {.__name__}'.format(f))
                rv = f(*args, **kwargs)
            return rv

        return wrapper

    return inner


@ntimes(2)
def add_hdec(x, y=10):
    return x + y


@ntimes(4)
def sub_hdec(x, y=10):
    return x - y