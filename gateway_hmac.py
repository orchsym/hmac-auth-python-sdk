# gateway_hmac.py
# -*- coding: UTF-8 -*-

import base64
import hashlib
import hmac
import re
from wsgiref.handlers import format_date_time
from datetime import datetime
from time import mktime


def create_date_header():
    now = datetime.now()
    stamp = mktime(now.timetuple())
    return format_date_time(stamp)

def get_headers_string(signature_headers):
    headers = ""
    for key in signature_headers:
        if headers != "":
            headers += " "
        headers += key
    return headers

def get_signature_string(signature_headers):
    sig_list = []
    sig_list.append("X-Date: ")
    sig_list.append(signature_headers["X-Date"])
    sig_list.append("\n")
    sig_list.append("Content-md5: ")
    sig_list.append(str(signature_headers["Content-md5"], encoding = "utf8"))
    sig_list.append("\n")
    sig_list.append(signature_headers["request-line"])
    return "".join(sig_list)

def md5_hash_base64(string_to_hash):
    m = hashlib.md5()
    m.update(string_to_hash)
    return base64.b64encode(m.digest())

def sha256_hash_base64(string_to_hash, secret):
    h = hmac.new(bytes(secret, encoding = "utf8"), (string_to_hash).encode("utf-8"), hashlib.sha256)
    return base64.b64encode(h.digest())

def generate_request_headers(username, secret, request_method, url):
    auth_header_template = (
        'hmac username="{}",algorithm="{}",headers="{}",signature="{}"'
    )
    algorithm = "hmac-sha256"
    date_header = create_date_header()
    signature_headers = {}
    signature_headers["X-Date"] = date_header
    base64md5 = md5_hash_base64(url.encode("utf8"))
    signature_headers["Content-md5"] = base64md5
    request_line = request_method + " " + url
    signature_headers["request-line"] = request_line
    headers = "X-Date Content-md5 request-line"
    signature_string = get_signature_string(signature_headers)
    signature_hash = sha256_hash_base64(signature_string, secret)
    auth_header = auth_header_template.format(
        username, algorithm, headers, signature_hash
    )

    request_headers = {
        "Authorization": auth_header,
        "X-Date": date_header,
        "Content-md5": base64md5,
    }

    return request_headers
