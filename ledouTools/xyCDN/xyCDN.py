#!/usr/bin/env python
# -*- coding: utf-8 -*-

# @Time    : 2017/12/4 14:49
# @Author  : Shawn
# @File    : xyCDN.py
# @Software: PyCharm

import ConfigParser
from hashlib import sha256
import time
import hmac
import base64
import json
import urllib2
import socket
import requests

cf = ConfigParser.ConfigParser()
cf.read("config.ini")

api_secret = cf.get("default", "api_secret")
api_key = cf.get("default", "api_key")


def json_post(url, dic):
    j_data = json.dumps(dic)
    # print j_data
    req = urllib2.Request(url, j_data, {'Content-Type': 'application/json'})
    result = urllib2.urlopen(req)
    response = result.read()
    result.close()
    return json.loads(response)


def get_data_from_api(post_data):
    query = {
        "api_key": api_key,
        "timestamp": int(time.time()),
        # "cmd": "get_domains"
    }

    h = hmac.new(api_secret, digestmod=sha256)
    query_dict = dict(query, **post_data)
    print query
    print type(query)
    print query_dict
    print type(query_dict)
    query_str = json.dumps(query_dict, separators=(',', ':'), sort_keys=True, ensure_ascii=False)
    print query_str
    h.update(query_str)
    print query_str
    sign = base64.b64encode(h.digest()).strip()

    query["signature"] = sign

    return json_post('http://openapi.peerstar.cn/api/', query)


print get_data_from_api({"cmd": "get_domains"})
# rst = json_post('http://openapi.peerstar.cn/api/', query)
# print type(rst)
# print rst
