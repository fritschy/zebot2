import json
import re
import sys

__errors = []


def handler_exit(status, **kwargs):
    """exit a handler wit the given status and some arguments in kwargs:
    lines=[str()]  -mandatory
    box=0|1
    wrap_single_lines=0|1
    wrap=0|1
    title=str()
    """
    if kwargs.get("errors") is None and len(__errors) != 0:
        kwargs["errors"] = __errors
    print(json.dumps(kwargs))
    sys.exit(status)


def log(e):
    """log an error, which will be returned to the caller on handler_exit().
    Usually this is a string or even a dict with some descriptive names."""
    __errors.append(e)


def get_args():
    """get handler arguments"""
    if len(sys.argv) < 4:
        handler_exit(1, error="not enough arguments to handler")

    # argv: ["./handlers/handler", "src", "dst", "!fortune[ -args]"]
    args = re.split(r'\s+', sys.argv[3], 1)

    return args[1] if len(args) != 1 else ""


def get_split_args():
    """get handler arguments, split into an argv like list (at whitespace)"""
    args = get_args()
    if len(args) != 0:
        return re.split(r'\s+', args)
    return []


def get_from():
    """get the message originator, i.e. who set the message"""
    return sys.argv[1]


def get_to():
    """get the message destination, e.g. where the message was sent to, e.g. a channel or you privately"""
    return sys.argv[2]
