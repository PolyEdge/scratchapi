#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Copyright (c) 2015 dyspore.cc
The MIT License (MIT)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files
(the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell  copies of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""


# ScratchAPI 2.0
# Written by Dylan5797 [http://dyspore.cc]
#  _____        _             _____ ______ ___ ______
# |  __ \      | |           | ____|____  / _ \____  |
# | |  | |_   _| | __ _ _ __ | |__     / / (_) |  / /
# | |  | | | | | |/ _  |  _ \|___ \   / / \__  | / /
# | |__| | |_| | | (_| | | | |___) | / /    / / / /
# |_____/ \__  |_|\__|_|_| |_|____/ /_/    /_/ /_/
#          __/ |
#         |___/

import collections as _collections
import traceback

import requests as _requests
import json as _json
import hashlib as _hashlib
import os as _os
import re as _re
import time as _time
import webbrowser as _web
import asyncio as _asyncio
import websockets as _websockets
import websockets.client as _websockets_client
import warnings as _warnings
import io as _io
import zipfile as _zipfile

# EXCEPTIONS

class ScratchAPIExceptionBase(BaseException): "Base exception for the scratchapi module"
class Unauthenticated(ScratchAPIExceptionBase): "Raised when an authenticated action is attempted without logging in"
class InvalidCSRF(ScratchAPIExceptionBase): "Raised when the CSRF token is invalid or not fetched"

# UTIL EXTENDS

class _ScratchUtils:
    def _tree(self, item, *args):
        path = args[:-1]
        default = args[-1]
        for x in path:
            try:
                item = item[x]
            except:
                return default
        return item


# CLIENT SESSION

class ScratchSession:
    def __init__(self, username=None, password=None, auto_login=True, retain_password=False):
        """Creates a scratch session. By default when a username and password are passed, the session automatically logs in.
        Setting retain_password to true will allow login() to be called later if necessary without needing the password"""

        self.SERVER = 'scratch.mit.edu'
        self.API_SERVER = 'api.scratch.mit.edu'
        self.PROJECTS_SERVER = 'projects.scratch.mit.edu'
        self.ASSETS_SERVER = 'assets.scratch.mit.edu'
        self.CDN_SERVER = 'cdn.scratch.mit.edu'
        self.CLOUD = 'clouddata.scratch.mit.edu'

        self.username = username
        self.password = None
        self.retain_password = retain_password

        self.http_session = _requests.session()

        self._save(username, password)
        if username != None and password != None and auto_login:
            self.login(username, password)

    def _save(self, username, password):
        self.username = username
        if self.retain_password:
            self.password = password
            
    def get_csrf(self):
        "Gets the CSRF token currently in use"
        return self.http_session.cookies.get('scratchcsrftoken')
    
    def get_session_id(self):
        "Gets the session ID currently in use"
        return self.http_session.cookies.get('scratchsessionsid')

    def _cookie_header(self): #ironically, CookieJar does not supply a direct method of fetching a cookie header, here is a (probably not up to spec) method to do so.
        cookies = []
        for name, value in self.http_session.cookies.get_dict().items():
            cookies.append(name + "=" + value)
        return "; ".join(cookies)

    def _get_headers(self, cookie=False):
        headers = {
            'X-Requested-With': 'XMLHttpRequest',
            'Referer': 'https://scratch.mit.edu/',
            'Origin': 'https://scratch.mit.edu'
        }
        if self.get_csrf() is not None:
            headers["X-CSRFToken"] = self.get_csrf()
        if cookie:
            headers["Cookie"] = self._cookie_header()
        return headers

    def authenticated(self):
        "Returns true if the session is authenticated, false otherwise"
        return self.get_session_id() is not None
    
    def rfa(self):
        "Raise-for-authentication. Raises an error if the session is not authenticated"
        _assert(self.authenticated(), Unauthenticated())

    def new_csrf(self):
        "Fetches a new CSRF token"
        self.http('/csrf_token/', auth=False)
        _assert(self.get_csrf() is not None, InvalidCSRF("the csrf token could not be fetched"))
        return self.get_csrf()

    def csrf(self):
        "Fetches a new CSRF token if needed"
        if self.get_csrf() is None:
            self.new_csrf()

    def login(self, *args):
        """Logs into scratch. If a username is supplied at class construction, a username does not need to be passed to login().
        If retain_password is set at class construction, no arguments need to be passed"""
        username = self.username
        password = self.password
        if len(args) == 0:
            assert username is not None and password is not None
        elif len(args) == 1:
            assert username is not None
            password = args[0]
        elif len(args) == 2:
            username = args[0]
            password = args[1]
        else:
            raise ValueError("wrong number of args")
        self.csrf()
        self._save(username, password)
        return self._login(username, password)

    def _login(self, username, password):
        return self.http('POST /login/', body={'username': username, 'password': password, 'csrftoken':self.get_csrf()}, auth=False)

    def logout(self):
        "Logs out of scratch. Does not clear CSRF token"
        return self.http('POST /accounts/logout/')

    def purge(self):
        "Clears all session data but DOES NOT log out. Use purge() only after logout()"
        self.http_session.cookies.clear()

    def session_valid(self):
        "Checks whether the session is valid. May raise an error if scratch is down or the internet connection is lost."
        return self.http('/messages/ajax/get-message-count/').status_code == 200

    def ahttp(self, *args, **kwargs):
        "Alias of http() with auth set to true"
        return self.http(*args, **kwargs, auth=True)

    def http(self, *args, **kwargs):
        """Makes a HTTP request. The request may be supplied in keyword arg only form, but can also be supplied using a specific argument pattern.

        Pattern syntax: http([SERVER], "[METHOD] PATH", [tuple(FIELDS)], PAYLOAD, **kwargs)
        > SERVER: optional server, defaults to self.SERVER
        > "METHOD PATH": a string containing an optional request method and the request path. Any text following a colon (:) will be treated as a field,
        similar to python %s syntax. When fields are specified, you must include a TUPLE, LIST, OR DICT of the fields directly after the path.
        > PAYLOAD: The request body. If not bytes, will default to UTF-8 encoding. You may pass a JSON serializable object and it will be converted to JSON internally.

        NOTE: eyword arguments will overwrite anything defined using the argument pattern defined above.
        Keyword args:
        > method: sets the request method
        > server: sets the server being requested to. Defaults to self.SERVER
        > body: The request body. Follows same behavior as PAYLOAD above
        > payload: alias of body
        > headers: dictionary of additional request headers to send to the server.
        > retry: number of retries on request failure (connection errors etc). Defaults to 3.
        > protocol: sets the request protocol. Defaults to https. Must be supported by the requests module.
        > port: sets the request port. The default port defined by requests will be used when none is passed.
        > auth: whether the request must be authenticated. Defaults to true. When set to true, an error will be raised if the session is not authenticated.
        > rfs: defaults to true. When true, calls request.raise_for_status() when completed.
        """
        request_protocol = "https"
        request_server = self.SERVER
        request_port = None
        request_method = "GET"
        request_path = None
        request_authenticated = False
        request_headers = {}
        request_cookies = self.http_session.cookies
        request_retries = 3
        request_body = None
        request_response = None
        request_raise_for_status = True

        if len(args) > 0:
            a0_split = args[0].split(" ", 1)
            if args[0].startswith('/'):
                request_path = args[0]
                args = args[1:]
            elif len(a0_split) >= 2 and a0_split[1].startswith("/"):
                request_method = a0_split[0].upper()
                request_path = a0_split[1]
                args = args[1:]
            else:
                request_server = args[0]
                if args[1].startswith('/'):
                    request_path = args[1]
                else:
                    a1_split = args[1].split(" ", 1)
                    request_method = a1_split[0].upper()
                    request_path = a1_split[1]
                args = args[2:]

            if ((not "field" in kwargs) or kwargs["field"]):
                path_build = ""
                index = 0
                field_arg = None
                fields = _collections.OrderedDict()
                for x in _re.split("(:[a-zA-Z0-9]+)", request_path):
                    if x.startswith(":"):
                        if field_arg is None:
                            assert len(args) > 0, "when supplying url fields using /:field/, supply a tuple, list or dictionary after the path or include (field=False) to disable field checking and use the raw URL."
                            field_arg = args[0] if type(args[0]) in [tuple, list, dict] else (args[0], )
                            args = args[1:]
                        if type(field_arg) == dict:
                            path_build += field_arg[x[1:]]
                        else:
                            path_build += field_arg[index]
                        index += 1
                    else:
                        path_build += x
                request_path = path_build

        if len(args) != 0:
            request_body = args[0]
            args = args[1:]

        if 'method' in kwargs:
            request_method = kwargs['method'].upper()
        if 'server' in kwargs:
            request_server = kwargs['server']
        if 'body' in kwargs:
            request_body = kwargs['body']
        if 'payload' in kwargs: #alias of body
            request_body = kwargs['payload']
        if 'headers' in kwargs:
            request_headers.update(kwargs['headers'])
        if 'retry' in kwargs:
            request_retries = kwargs['retry']
        if 'protocol' in kwargs:
            request_protocol = kwargs['protocol']
        if 'port' in kwargs:
            request_port = kwargs['port']
        if 'auth' in kwargs:
            request_authenticated = kwargs['auth']
        if 'rfs' in kwargs:
            request_raise_for_status = kwargs['rfs']

        request_headers.update(self._get_headers())

        if request_authenticated:
            _assert(self.get_session_id() is not None, Unauthenticated())
            _assert("X-CSRFToken" in request_headers, InvalidCSRF())
            _assert(request_headers["X-CSRFToken"] is not None, InvalidCSRF())

        if not ((type(request_body) == bytes) or request_body is None):
            if type(request_body) in [list, dict]:
                request_body = _json.dumps(request_body).encode("utf-8")
            elif type(request_body) == str:
                request_body = request_body.encode("utf-8")
            else:
                raise TypeError("strange request body. expected bytes, str or json serializable object")
        if request_body is not None:
            request_headers["content-length"] = len(request_body)
        request_headers = {x:(str(request_headers[x]) if not isinstance(request_headers[x], (str, bytes)) else request_headers[x]) for x in request_headers}
        request_url = request_protocol + "://" + request_server + (":" + str(request_port) if request_port != None else "") + request_path
        request_unprepared = _requests.Request(method=request_method.upper(), url=request_url, headers=request_headers, cookies=self.http_session.cookies)
        if (request_body is not None):
            request_unprepared.data = request_body
        request_prepared = request_unprepared.prepare()

        for x in range(0, request_retries + 1):
            if x >= request_retries:
                raise ConnectionError('Connection failed on all ' + str(request_retries) + ' attempts')
            try:
                request_response = self.http_session.send(request_prepared)
                break
            except _requests.exceptions.BaseHTTPError:
                continue
        if request_raise_for_status and request_response is not None:
            request_response.raise_for_status()
        return request_response

# AUTH HELPER

class _ScratchAuthenticatable:
    """"Represents an online scratch entity that may contain additional features when the client is authenticated.
    An instance of ScratchSession may be stored in an instance of ScratchAuthenticatable in order for it to function without requiring a session to be passed every time"""

    def _put_auth(self, session): #used to set the auth session by a parent
        self._session = session
        return self

    def _auth(self, session: ScratchSession=None) -> ScratchSession():
        "alias of _session(session, auth=True)"
        return self._session(session=session, auth=True)

    def _session(self, session: ScratchSession=None, auth=False) -> ScratchSession():
        """returns the session the authenticatable is using unless another session is specified in the arguments as an override. will make a new session if needed.
        if auth is set to true and the session is not authenticated, will raise an error"""
        if session is None:
            if self._session == None:
                self._session = ScratchSession()
            session = self._session
        if auth:
            _assert(session.authenticated(), Unauthenticated())
        session.csrf()
        return session

    def authenticate(self, session: ScratchSession):
        "authenticates the object with the given session."
        self._session = session

class ScratchAPI:
    "NOT UPDATED YET! A wrapper"
    def __init__(self, *args, **kwargs):
        auto_csrf = True
        if "auto_csrf" in kwargs:
            auto_csrf = kwargs["auto_csrf"]
            del kwargs["auto_csrf"]

        if len(args) >= 1 and type(args[0]) == ScratchSession:
            self.session = args[0]
        else:
            self.session = ScratchSession(*args, **kwargs)

        if auto_csrf:
            self.session.csrf()

    def projects_legacy_get(self, project_id):
        return self.session.http(path='/internalapi/project/' + project_id + '/get/', server=self.session.PROJECTS_SERVER).json()

    def projects_legacy_set(self, project_id, payload):
        return self.session.http(server=self.session.PROJECTS_SERVER, path='/internalapi/project/' + project_id + '/set/', payload=payload, method='post')

    def projects_get_meta(self, project_id):
        return self.session.http(path='/api/v1/project/' + str(project_id) + '/?format=json').json()

    def projects_get_remixtree(self, project_id):
        return self.session.http(path='/projects/' + str(project_id) + '/remixtree/bare/').json()

    def _tools_verifySession(self):
        return self.session.http(path='/messages/ajax/get-message-count/', port=None).status_code == 200

    def _backpack_getBackpack(self):
        return self.session.http(path='/internalapi/backpack/' + self.lib.set.username + '/get/').json()

    def _backpack_setBackpack(self, payload):
        return self.session.http(server=self.CDN_SERVER, path='/internalapi/backpack/' + self.lib.set.username + '/set/', method="post", payload=payload)

    def _userpage_setStatus(self, payload):
        p2 = self.session.http(path='/site-api/users/all/' + self.lib.set.username).json()
        p = {}
        for i in p2:
            if i in ['comments_allowed', 'id', 'status', 'thumbnail_url', 'userId', 'username']:
                p[i] = p2[i]
        p['status'] = payload
        return self.session.http(path='/site-api/users/all/' + self.lib.set.username, method="put", payload=_json.dumps(p))

    def _userpage_toggleComments(self):
        return self.session.http(path='/site-api/comments/user/' + self.lib.set.username + '/toggle-comments/', method="put")

    def _userpage_setBio(self, payload):
        p2 = self.session.http(path='/site-api/users/all/' + self.lib.set.username).json()
        p = {}
        for i in p2:
            if i in ['comments_allowed', 'id', 'bio', 'thumbnail_url', 'userId', 'username']:
                p[i] = p2[i]
        p['bio'] = payload
        return self.session.http(path='/site-api/users/all/' + self.lib.set.username, method="put", payload=_json.dumps(p))

    def _users_get_meta(self, usr):
        return self.session.http(path='/users/' + usr, server=self.API_SERVER).json()

    def _users_follow(self, usr):
        return self.session.http(path='/site-api/users/followers/' + usr + '/add/?usernames=' + self.lib.set.username, method='PUT')

    def _users_unfollow(self, usr):
        return self.session.http(path='/site-api/users/followers/' + usr + '/remove/?usernames=' + self.lib.set.username, method='PUT')

    def _users_comment(self, user, comment):
        return self.session.http(path='/site-api/comments/user/' + user + '/add/', method='POST', payload=_json.dumps({"content":comment,"parent_id":'',"commentee_id":''}))

    def _studios_comment(self, studioid, comment):
        return self.session.http(path='/site-api/comments/gallery/' + str(studioid) + '/add/', method='POST', payload=_json.dumps({"content":comment,"parent_id":'',"commentee_id":''}))

    def _studios_get_meta(self, studioid):
        return self.session.http(path='/site-api/galleries/all/' + str(studioid)).json()

    def _studios_invite(self, studioid, user):
        return self.session.http(path='/site-api/users/curators-in/' + str(studioid) + '/invite_curator/?usernames=' + user, method='PUT')

    def _projects_comment(self, project_id, comment):
        return self.session.http(path='/site-api/comments/project/' + str(project_id) + '/add/', method='POST', payload=_json.dumps({"content":comment,"parent_id":'',"commentee_id":''}))

    def _cloud_setvar(self, var, value, project_id):
        return self._cloud_send('set', project_id, {'name': '☁ ' + var, 'value': value})

    def _cloud_makevar(self, var, value, project_id):
        return self._cloud_send('create', project_id, {'name': '☁ ' + var})

    def _cloud_rename_var(self, oldname, newname, project_id):
        self._cloud_send('rename', project_id, {'name': '☁ ' + oldname, 'new_name': '☁ ' + newname})

    def _cloud_delete_var(self, name, project_id):
        self._cloud_send('delete', project_id, {'name':'☁ ' + name})

    def _cloud_getvar(self, var, project_id):
        return self._cloud_getvars(project_id)[var]

    def _cloud_getvars(self, project_id):
        dt = self.session.http(path='/varserver/' + str(project_id)).json()['variables']
        vardict = {}
        for x in dt:
            xn = x['name']
            if xn.startswith('☁ '):
                vardict[xn[2:]] = x['value']
            else:
                vardict[xn] = x['value']
        return vardict

    def _cloud_send(self, method, project_id, options):
        cloudToken = self.session.http(method='GET', path='/projects/' + str(project_id) + '/cloud-data.js').text.rsplit('\n')[-28].replace(' ', '')[13:49]
        bc = _hashlib.md5()
        bc.update(cloudToken.encode())
        data = {
            "token": cloudToken,
            "token2": bc.hexdigest(),
            "project_id": str(project_id),
            "method": str(method),
            "user": self.lib.set.username,
        }
        data.update(options)
        return self.session.http(method='POST', path='/varserver', payload=_json.dumps(data))

        #self.HEADERS['Cookie'] = 'scratchcsrftoken=' + self.lib.utils.session.cookies.get_dict()['scratchcsrftoken'] + '; scratchsessionsid=' + self.lib.utils.session.cookies.get('scratchsessionsid') + '; scratchlanguage=en'


    def _assets_get(self, md5):
        return self.session.http(path='/internalapi/asset/' + md5 + '/get/', server=self.ASSETS_SERVER).content
    def _assets_set(self, md5, content, content_type=None):
        if not content_type:
            if _os.path.splitext(md5)[-1] == '.png':
                content_type = 'image/png'
            elif _os.path.splitext(md5)[-1] == '.svg':
                content_type = 'image/svg+xml'
            elif _os.path.splitext(md5)[-1] == '.wav':
                content_type = 'audio/wav'
            else:
                content_type = 'text/plain'
        headers = {'Content-Length':str(len(content)),
                   'Origin':'https://cdn.scratch.mit.edu',
                   'Content-Type':content_type,
                   'Referer':'https://cdn.scratch.mit.edu/scratchr2/static/__cc77646ad8a4b266f015616addd66756__/Scratch.swf'}
        return self.session.http(path='/internalapi/asset/' + md5 + '/set/', method='POST', server=self.ASSETS_SERVER, payload=content)
    def _users_get_message_count(self, user=None):
        if user == None:
            user = self.lib.set.username
        return self.session.http(path='/proxy/users/' + user + '/activity/count', server=self.API_SERVER).json()['msg_count']
    def _get_message_html(self):
        return self.session.http(path='/messages/')

class ScratchUserSession:
    def __init__(self, *args, **kwargs):
        _warnings.warn("""Scratch user sessions and interfacing with the API have been seperated into 2 classes, ScratchSession and ScratchAPI.
        ScratchUserSession has been made an alias of ScratchAPI, which will still accept a username and password to create its own ScratchSession with.
        This alias may be removed in the future, it is suggested that you change over to the new class names.""")
        super().__init__(*args, **kwargs)

# OFFLINE PROJECTS

class ScratchProject:
    def __init__(self, load=None, reader=None):
        """represents an offline scratch project. In order to upload a scratch project, you must create an online project first
        (using ScratchAPI.new_project() or creating a new OnlineScratchProject)"""
        self.json = None
        self.assets = {}
        self.reader = None
        self.file = None
        if (load != None):
            ScratchProject.load(load, reader=reader)

    def load(self, stream, reader=None):
        project_json, stream = self._stream(stream)
        if reader == None:
            reader = _ScratchProjectReader.get_reader(project_json)
        assert reader != None, "couldn't read this file. no reader accepted the JSON content."
        self.json = project_json
        self.reader = reader
        self.file = stream

    def _stream(self, stream):
        try:
            scratch_file = ScratchProject._get_zipfile(stream)
        except:
            raise ValueError("scratch file is invalid. NOTE: scratch 1.4 is not supported")
        json_filename = ([x.filename for x in scratch_file.filelist if x.filename == 'project.json'] + [x.filename for x in scratch_file.filelist if x.filename.endswith('project.json')]) #have seen prefixed project.json files before that scratch still opens ...lol
        json_file = scratch_file.open(json_filename)
        project_json = _json.loads(json_file.read().decode('utf-8'))
        json_file.close()
        return (project_json, scratch_file)

    def _assets(self, stream):
        pass # TODO

    def _get_zipfile(*args):
        stream = args[-1]
        if type(stream) == bytes:
            stream = _io.BytesIO(stream)
        return _zipfile.ZipFile(stream)

    def get_asset(self, name):
        if name in self.assets:
            return self.assets[name]
        self.read_asset()
        return None

    def put_asset(self, data: bytes, filetype):
        "adds an asset to the project"
        md5 = _hashlib.md5(data).hexdigest()
        self.assets[md5 + "." + filetype] = data
        return md5

    def del_asset(self, filename):
        while filename in self.assets:
            del self.assets[filename]

    #Override methods

    def read_asset(self, name):
        "will return an asset with the name specified"
        if name in self.assets:
            return self.assets[name]
        return None

class _ScratchProjectReader(_ScratchUtils):
    def __init__(self, parent):
        self.parent = parent

    def get_reader(*args):
        parent = args[-1]
        for reader in _ScratchProjectReader.__subclasses__():
            instance = reader(parent)
            if instance.includes(args[-1]):
                return instance
        return None

    def includes(self, json):
        "returns true if the passed json is implemented by this reader"
        return False

    def from_sb2(self, zipfile):
        "converts a sb2 to json and assets"
        raise NotImplemented()

    def to_sb2(self, json, assets):
        "converts json and assets to a sb2 file"
        raise NotImplemented()

    def get_asset_list(self, json):
        "creates an asset list from the passed json object"
        raise NotImplemented()


class _ScratchReader20(_ScratchProjectReader):
    def to_sb2(self, json, assets):
        raise NotImplemented("not currently implemented.")

    def from_sb2(self, zipfile):
        pass


# ONLINE PROJECTS

class ScratchProjectOnlineProxy(ScratchProject, _ScratchAuthenticatable):
    def __init__(self, project_id=None):
        """a proxy implementation of ScratchProject representing a scratch project stored on MIT servers
        NOTE: assets will not be re-uploaded on save unless they are downloaded. This API does not provide high level
        project modification capabilities. If you wish to change the project assets, you must call project.put_asset()
        with any assets that you are adding to project, unless you know for sure they exist on the scratch assets server."""
        super().__init__(self, load=project_id, instance=self)

    def load(*args, reader=None, instance=None):
        pass # TODO



class OnlineScratchProject(_ScratchAuthenticatable, _ScratchUtils):
    def __init__(self, project_id=None):
        "Represents a project stored on the scratch website. May not be uploaded to the website yet if id is none"
        self.project_id = project_id
        self.loaded = False

        self.author = None
        self.shared = None
        self.comments_enabled = None
        self.created = None
        self.modified = None
        self.shared = None
        self.thumbnails = None
        self.instructions = None
        self.credits = None
        self.remix_original = None
        self.remix_parent = None
        self.views = None
        self.loves = None
        self.favorites = None
        self.comments = None
        self.remixes = None

        self.project = None

    def _ensure_loaded(self, session=None):
        if not self.loaded:
            return self.load(session)

    def _put_data(self, data):
        #self.author = ??
        self.shared = self._tree(data, "is_published", False)
        self.comments_enabled = self._tree(data, "comments_allowed", False)
        self.shared = self._tree(data, "is_published", False)

    def created(self):
        "returns true if the project has an ID on the scratch website"
        return self.project_id is not None

    def load(self, session=None):
        "downloads metadata from the scratch website"
        assert self.created(), "the project must be created to be loaded"
        session = self._session(session)
        data = session.http(session.API_SERVER, "/projects/:project", self.project_id).json()

    def get_project(self, session=None):

        assert self.created()
        session = self._session(session)
        project = ScratchProjectOnlineProxy(self.project_id)


# CLOUD SESSIONS

class _CloudSessionWatchdog:
    def __init__(self, instance):
        self.enabled = True
        self.instance = instance
        self.read_last = _time.time()
        self.read_timeout = 45 # after this many seconds with no reads, the connection will be reestablished

    def reconnect_needed(self):
        return (_time.time() > self.read_last + self.read_timeout)

    def reset_read(self):
        self.read_last = _time.time()

    async def handle_connection(self):
        if (not self.enabled) or not (self.instance._connected):
            return
        if (not (self.instance.socket.state in [_websockets_client.OPEN, _websockets_client.CONNECTING])) or self.reconnect_needed():
            self.instance._debug("watchdog: reconnect -> " + str(self.instance.socket.state))
            self.reset_read()
            await AIOCloudSession.reconnect(self.instance)

class AIOCloudSession: # not sure exactly the usage cases of this thing because the main api isn't AIO but better to include this than not
    def __init__(self, *args, loop=None, **kwargs):
        """Creates an asyncio based cloud session. The event loop used defaults to asyncio.get_event_loop() unless one is passed with (loop=)
        Passing a project ID as the first argument will set the project_id parameter in the created instance and will be connected to using connect()
        A session must be provided in the form of a ScratchSession, ScratchAPI or username and password."""

        self.event_loop = loop or _asyncio.get_event_loop()
        self.project_id = None
        self.session = None

        if len(args) > 0 and (type(args[0]) == int or (len(args) == 3 and type(args[0]) == str)):
            self.project_id = str(args[0])
            args = args[1:]
        if len(args) > 0:
            if type(args[0]) == ScratchSession:
                self.session = args[0]
            elif type(args[0]) == ScratchAPI:
                self.session = args[0].session
            elif type(args[0]) in [list, tuple]:
                self.session = ScratchSession(args[0][0], args[0][1], **kwargs)
            else:
                self.session = ScratchSession(*args, **kwargs)

        self.watchdog = _CloudSessionWatchdog(self)
        self._connected = False #whether the client should be connected. could be incorrect as to whether the socket is actually connected or not. use connected()
        self._debug_enabled = False #displays diagnostics when set to true

        self.variables = _AIOCloudVariablesList(self)
        self._client_outbound = []
        self._client_inbound = []
        self.socket = None

        # self._rollover = []

    def _debug(self, message):
        if self._debug_enabled:
            print(message)

    def _check_connected(self):
        assert self._connected, "The client is not connected"
        assert self.socket != None, "No connection was established"

    async def connect(self, project_id=None):
        """connects to the cloud data server. specifying a project_id will overwrite any id given when the class is constructed.
        one must be given at class contruction or passed to connect() or an error will be raised"""
        self.project_id = project_id or self.project_id
        assert self.project_id != None
        assert self.session.authenticated()
        _websockets_client.USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.86 Safari/537.36" #look like a normal client if this works the way i expect it does :sunglasses:
        self._debug("connect: establish")
        self.socket = await _websockets_client.connect("ws://" + self.session.CLOUD + "/", loop=self.event_loop, extra_headers=[(key, value) for key, value in self.session._get_headers(cookie=True).items()])
        self.socket.timeout = 30 #not sure how big this is server side but this number will be used to mark the socket as timed out after a small period of no reads
        self._connected = True
        self.watchdog.reset_read()
        self._debug("connect: handshake")
        await AIOCloudSession._write_packet(self, self._create_packet('handshake', {}))
        self._debug("connect: write()")
        await AIOCloudSession._write(self)
        self._debug("connect: complete")

    async def disconnect(self, timeout=0.25):
        "disconnects from the cloud data server"
        try:
            await _asyncio.wait_for(self.socket.close(), timeout)
        except _asyncio.TimeoutError: # dirty disconnect but oh well i guess
            del self.socket
            self.socket = None
        self._connected = False

    async def reconnect(self):
        "reconnects the client to the cloud data server, if connected, otherwise an error is raised"
        self._check_connected()
        self._debug("reconnect: disconnect")
        await AIOCloudSession.disconnect(self)
        self._debug("reconnect: connect")
        await AIOCloudSession.connect(self)

    async def keep_alive(self):
        "keeps the connection alive if connected"
        await AIOCloudSession._read(self, 0)

    def _create_packet(self, method, options=None):
        "creates a cloud data packet with the set method and options and parameters"
        base_packet = {
            'user': self.session.username,
            'project_id': str(self.project_id),
            'method': method
        }
        packet = (options or {}).copy()
        packet.update(base_packet)
        return packet

    async def _read(self, timeout=0, max_count=None):
        "reads updates from the websocket and keeps the connection alive"
        AIOCloudSession._check_connected(self)
        await self.watchdog.handle_connection()
        max_count = float('inf') if max_count is None else max_count - 1
        updates = []
        count = -1
        while count < max_count:
            count += 1
            data = None
            try:
                await _asyncio.sleep(0)
                data = await _asyncio.wait_for(self.socket.recv(), timeout)
            except _asyncio.TimeoutError:
                break
            except _websockets.ConnectionClosed:
                await AIOCloudSession.reconnect()
                continue
            if (data is None) or (data == b""):
                break
            try:
                packet = _json.loads(data)
            except:
                traceback.print_exc()
                continue
            updates.append(packet)
            self._client_inbound.append(packet)
            if ("method" in packet) and (packet["method"].lower().strip() == "set"):
                self.variables._put(packet["name"], packet["value"])
        self.watchdog.reset_read()
        return updates

    async def _write(self):
        "sends all queued packets to the cloud data server"
        self._debug("write: keep alive")
        await AIOCloudSession.keep_alive(self)
        self._debug("write: write")
        for packet in self._client_outbound.copy():
            del self._client_outbound[0]
            ob = (_json.dumps(packet) + '\n').encode('utf-8')
            try:
                await AIOCloudSession._write_packet(self, packet)
            except _websockets.ConnectionClosed:
                self._debug("write: closed and reconnecting")
                self._client_outbound.insert(0, packet)
                await AIOCloudSession.reconnect(self)
                return
            self._debug("write: success")
        self._debug("write: complete")

    async def _write_packet(self, packet):
        "sends a packet to the cloud data server"
        ob = (_json.dumps(packet) + '\n').encode('utf-8')
        self._debug("write_packet: sending " + str(ob))
        await self.socket.send(ob)

    async def _send(self, *args, **kwargs):
        "queues a packet to be sent to the cloud data server. in a normal situation, the packet will be sent immediately"
        packet = self._create_packet(*args, **kwargs)
        self._debug("send: queueing " + str(packet))
        self._client_outbound.append(packet)
        self._debug("send: write()")
        await AIOCloudSession._write(self)
        self._debug("send: complete")

    async def get_updates(self):
        "fetches a list of packets received from the server"
        await AIOCloudSession._read(self, 0)
        updates = self._client_inbound.copy()
        self._client_inbound.clear()
        return updates

    async def set_var(self, name, value):
        "sets an existing cloud variable. a cloud symbol and space (☁ ) must be included in the name if present on the server"
        await AIOCloudSession._send(self, 'set', {'name': name, 'value': value})
        self.variables._put(name, value)

    async def create_var(self, name, value=None):
        "creates a cloud variable. a cloud symbol and space (☁ ) must be included in the name if present on the server"
        value = value or 0
        await AIOCloudSession._send(self, 'create', {'name': name, 'value': value})

    async def rename_var(self, old_name, new_name):
        "changes the name of an existing cloud variable. a cloud symbol and space (☁ ) must be included in both names if present on the server"
        await AIOCloudSession._send(self, 'rename', {'name': old_name, 'new_name': new_name})

    async def delete_var(self, name):
        "deletes an existing cloud variable. a cloud symbol and space (☁ ) must be included in the name if present on the server"
        await AIOCloudSession._send(self, 'delete', {'name': name})

    async def get_var(self, name, timeout=0):
        """[it is recommended to use session.variables.get(name, default) instead]
        gets the value a cloud variable, raises KeyError if not found. a cloud symbol and space (☁ ) must be included in the name if present on the server"""
        await AIOCloudSession._read(self, timeout=timeout)
        return self.variables[name]

    async def get_vars(self, timeout=0):
        """returns a dictionary of all tracked cloud variables"""
        await AIOCloudSession._read(self, timeout=timeout)
        return self.variables.variables

class CloudSession(AIOCloudSession): # not sure of standard conventions for running asyncs like this properly.
                                     # async isnt even supposed to be used like this but it's a documented in a way that
                                     # that beginners struggle to understand, and syncronous programming is the best start
                                     # </opinion>
    def __init__(self, *args, **kwargs):
        """Synchronous wrapper for AIOCloudSession, mostly compatable with the old CloudSessiom.
        Passing a project ID as the first argument will connect the the project's cloud right away.
        A session must be provided in the form of a ScratchSession, ScratchAPI or username and password."""
        super().__init__(*args, **kwargs)
        self.variables = _CloudVariablesList(self)


    def connect(self, *args, **kwargs):
        return self.event_loop.run_until_complete(super().connect(*args, **kwargs))

    def disconnect(self, *args, **kwargs):
        return self.event_loop.run_until_complete(super().disconnect(*args, **kwargs))

    def reconnect(self, *args, **kwargs):
        return self.event_loop.run_until_complete(super().reconnect(*args, **kwargs))

    def keep_alive(self, *args, **kwargs):
        return self.event_loop.run_until_complete(super().keep_alive(*args, **kwargs))

    def _read(self, *args, **kwargs):
        return self.event_loop.run_until_complete(super()._read(*args, **kwargs))

    def _write(self, *args, **kwargs):
        return self.event_loop.run_until_complete(super()._write(*args, **kwargs))

    def _write_packet(self, *args, **kwargs):
        return self.event_loop.run_until_complete(super()._write_packet(*args, **kwargs))

    def _send(self, *args, **kwargs):
        return self.event_loop.run_until_complete(super()._send(*args, **kwargs))

    def get_updates(self, *args, **kwargs):
        return self.event_loop.run_until_complete(super().get_updates(*args, **kwargs))

    def set_var(self, *args, **kwargs):
        return self.event_loop.run_until_complete(super().set_var(*args, **kwargs))

    def create_var(self, *args, **kwargs):
        return self.event_loop.run_until_complete(super().create_var(*args, **kwargs))

    def rename_var(self, *args, **kwargs):
        return self.event_loop.run_until_complete(super().rename_var(*args, **kwargs))

    def delete_var(self, *args, **kwargs):
        return self.event_loop.run_until_complete(super().delete_var(*args, **kwargs))

    def get_var(self, *args, **kwargs):
        return self.event_loop.run_until_complete(super().get_var(*args, **kwargs))

    def get_vars(self, *args, **kwargs):
        return self.event_loop.run_until_complete(super().get_vars(*args, **kwargs))


class _AIOCloudVariablesList:
    def __init__(self, parent: AIOCloudSession):
        self.parent = parent
        self.variables = {}

    def _put(self, var, value):
        self.variables[var] = value

    async def _aio_get(self, name, *args, **kwargs):
        await AIOCloudSession._read(self.parent, 0)
        has_default = len(args) == 1 or "default" in kwargs
        default = args[0] if len(args) == 1 else None
        default = kwargs["default"] if "default" in kwargs else default
        if name in self.variables:
            return self.variables[name]
        elif not name.startswith("☁ "):
            return await _AIOCloudVariablesList._aio_get(self, "☁ " + name, *args, **kwargs)
        elif has_default:
            return default
        if name.startswith("☁ "):
            raise ValueError(
                "no variable with name " + name + ". if you specified the variable without a cloud, neither versions were found.")
        raise ValueError("no variable with name " + name)

    async def _aio_set(self, name, value, auto_cloud=True):
        await AIOCloudSession._read(self.parent, 0)
        if (not name in self.variables) and (not name.startswith("☁ ") and auto_cloud):
            return await _AIOCloudVariablesList._aio_set(self, "☁ " + name, value, False)
        await AIOCloudSession.set_var(self.parent, name, value)

    async def get(self, *args, **kwargs):
        "gets a cloud variable, returns default if specified in keyword args. raises ValueError otherwise. "
        return await _AIOCloudVariablesList._aio_get(self, *args, **kwargs)

    async def set(self, *args, **kwargs):
        """will attempt set any variable including ones that do not exist.
        when auto_cloud is true, will append a cloud to the variables name if it is not found in the list.
        NOTE: for future compatability, the type of the value is preserved. make sure to use NUMBER TYPES ONLY"""
        return await _AIOCloudVariablesList._aio_set(self, *args, **kwargs)

    def __getitem__(self, *args):
        raise NotImplemented("cannot use a __getitem__ implementation with async implementation")

    def __setitem__(self, *args):
        raise NotImplemented("cannot use a __setitem__ implementation with async implementation")

class _CloudVariablesList(_AIOCloudVariablesList):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get(self, *args, **kwargs):
        return self.parent.event_loop.run_until_complete(super()._aio_get(*args, **kwargs))

    def set(self, *args, **kwargs):
        return self.parent.event_loop.run_until_complete(super()._aio_set(*args, **kwargs))

    def __getitem__(self, *args):
        return self.get(*args)

    def __setitem__(self, args, value):
        args = args if type(args) == tuple else (args, )
        return self.set(*args[0:1], value, *args[1:])

class __docs_view():
    "Call __doc__() to view the scratchapi docs online"
    def __call__(self):
        _web.open("https://github.com/PolyEdge/scratchapi/wiki/")
    def __repr__(self):
        return "See https://github.com/PolyEdge/scratchapi/wiki/ or call this object."
__doc__ = __docs_view()

def _assert(condition, exception=None):
    if not condition:
        raise exception or AssertionError()

print("t")