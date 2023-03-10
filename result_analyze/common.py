#!/usr/bin/env python3

import time
import functools
import socket
import struct

col_dic = {
    'd': 30, 'r': 31, 'g': 32, 'y': 33,
    'b': 34, 'p': 35, 'c': 36, 'w': 37
}

def string_decorator(basic:str, / , col:str='w', b:bool=False) -> str:
    return f"\033[{'1;' if b else '0;'}{col_dic[col]}m{basic}\033[0m"


import logging
logging.basicConfig(level=logging.INFO,
                    format=string_decorator("[%(asctime)s %(levelname)s]", 'c') + " %(message)s",
                    datefmt='%Y-%m-%d %H:%M:%S')


def call_log(text:str=''):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kw):
            if len(text) == 0 or text.isspace():
                print(string_decorator(f'[Call Function {func.__name__}()]', 'g', True))
            else:
                print(string_decorator(f'[Call Function {func.__name__}()]: {text}', 'g', True))
            return func(*args, **kw)
        return wrapper
    return decorator


def time_log(func):
    @functools.wraps(func)
    def wrapper(*args, **kw):
        _time_str = time.time()
        res = func(*args, **kw)
        _time_stp = time.time()
        print(string_decorator(f'[Function {func.__name__}() Finished] cost time: {_time_stp - _time_str:6.3f} s.', 'p', True))
        return res
    return wrapper


def addr_num2str(num_addr:int) -> str:
    return socket.inet_ntoa(struct.pack('I',socket.htonl(num_addr)))

def addr_str2num(str_addr:str) -> int:
    return socket.ntohl(struct.unpack("I",socket.inet_aton(str(str_addr)))[0])

