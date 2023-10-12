from pydoc import locate
from typing import Optional
import json
import argparse

from PIL import Image

from ucall.client import Client


def get_kwargs(buffer):
    kwargs = {}
    if buffer is not None:
        for arg in buffer:
            sp = None
            if '=' in arg:
                sp = arg.split('=')
            else:
                raise KeyError('Missing key in kwarg argument')
            kwargs[sp[0]] = sp[1]
    return kwargs


def cast(value: str, type_name: Optional[str]):
    """Casts a single argument value to the expected `type_name` or guesses it."""
    if type_name is None:
        if value.isdigit():
            return int(value)
        if value.replace('.', '', 1).isdigit():
            return float(value)
        if value in ['True', 'False']:
            return bool(value)
        return value

    type_name = type_name.lower()
    if type_name == 'image':
        return Image.open(value)
    if type_name == 'binary':
        return open(value, 'rb').read()

    return locate(type_name)(value)


def fix_types(args, kwargs):
    """Casts `args` and `kwargs` to expected types."""
    for i in range(len(args)):
        if ':' in args[i]:
            val, tp = args[i].split(':')
            args[i] = cast(val, tp)
        else:
            args[i] = cast(args[i], None)
    keys = list(kwargs.keys())
    for k in keys:
        if ':' in k:
            key, tp = k.split(':')
            val = kwargs.pop(k)
            kwargs[key] = cast(val, tp)
        else:
            kwargs[k] = cast(kwargs[k], None)


def add_specials(kwargs: dict, special: Optional[list[str]], type_name: str):
    if special is None:
        return
    for x in special:
        if not '=' in x:
            raise KeyError(f'Missing key in {type_name} argument')
        k, v = x.split('=')
        kwargs[k + ':' + type_name] = v


def cli():
    parsed = get_parser().parse_args()
    kwargs = get_kwargs(parsed.kwargs)
    args = parsed.positional if parsed.positional else []

    add_specials(kwargs, parsed.file, 'binary')
    add_specials(kwargs, parsed.image, 'image')

    fix_types(args, kwargs)
    client = Client(uri=parsed.uri, port=parsed.port, use_http=True)
    res = getattr(client, parsed.method)(*args, **kwargs)

    if parsed.format == 'raw':
        print(json.dumps(res.data, indent=4))
    else:
        try:
            print(getattr(res, parsed.format))
        except Exception as err:
            print('Error:', err)


def get_parser():
    parser = argparse.ArgumentParser(description='UCall Client CLI')
    parser.add_argument('method', type=str, help='Method name')

    parser.add_argument('--uri', type=str, default='localhost',
                        help='Server URI')
    parser.add_argument('-p', '--port', type=int, default=8545,
                        help='Server port')

    parser.add_argument('kwargs', nargs='*', help='KEY[:TYPE]=VALUE arguments')
    parser.add_argument('-f', '--file', nargs='*', help='Binary files')
    parser.add_argument('-i', '--image', nargs='*', help='Image files')

    parser.add_argument('--positional', nargs='*',
                        help='Switch to positional arguments VALUE[:TYPE]')

    parser.add_argument('--format', type=str,
                        choices=['json', 'bytes', 'numpy', 'image', 'raw'], default='raw',
                        help='How to parse and format the response')
    return parser


if __name__ == '__main__':
    cli()
