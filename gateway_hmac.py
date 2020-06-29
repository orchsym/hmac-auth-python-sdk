# gateway_hmac.py
# -*- coding: UTF-8 -*-

import base64
import hashlib
import hmac
import re

from datetime import datetime
from time import mktime
from urlparse import urlparse
from wsgiref.handlers import format_date_time


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
    sig_list.append(signature_headers["Content-md5"].decode("utf8"))
    sig_list.append("\n")
    sig_list.append(signature_headers["request-line"])
    return "".join(sig_list)

def md5_hash_base64(string_to_hash):
    m = hashlib.md5()
    m.update(string_to_hash)
    return base64.b64encode(m.digest())

def sha256_hash_base64(string_to_hash, secret):
    h = hmac.new(bytes(secret.decode("utf8")), string_to_hash.encode("utf8"), hashlib.sha256)
    return base64.b64encode(h.digest())

def extract_path(url):
    url_object = urlparse(url)
    path = url_object.path

    if url_object.query != '':
        path += '?' + url_object.query

    # the env prefix of URI, like /env-101, is used for gateway environment proxy,
    # and will not be used in HMAC signature computation.
    return re.sub(r'^/env-\d+/', '/', path)


def generate_request_headers(username, secret, request_method, url):
    """
    Generate request headers which will be required in HMAC authorization.

    Parameters:
    - username (string): HMAC username
    - secret (string): HMAC secret 
    - request_method (string): the  method of request to be sent, like 'GET', 'POST'
    - url (string): the URL of the request to be sent. 

    Returns:
    dict: Headers which are required in request authorization
    """

    auth_header_template = (
        'hmac username="{}",algorithm="{}",headers="{}",signature="{}"'
    )
    algorithm = "hmac-sha256"
    headers = "X-Date Content-md5 request-line"

    date_header = create_date_header()
    signature_headers = {}
    path = extract_path(url)

    signature_headers["X-Date"] = date_header
    base64md5 = md5_hash_base64(path.encode("utf8"))

    signature_headers["Content-md5"] = base64md5
    request_line = request_method.upper() + " " + path

    signature_headers["request-line"] = request_line
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

if __name__ == "__main__":
    url = "https://172.18.28.240/env-101/por-1/test/api/users/2"
    headers = generate_request_headers("tom", "passw0rd", "GET", url)

    print(headers)

    # import requests
    # r = requests.get(url, verify=False, headers=headers)
    # print(r.text)
