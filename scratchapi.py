#!/usr/bin/env python3

"""
The MIT License (MIT)
Copyright (c) 2015 Dylan Beswick

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


# ScratchAPI 1.0
# Written by Dylan5797 [https://dylan5797.github.io]
#  _____        _             _____ ______ ___ ______
# |  __ \      | |           | ____|____  / _ \____  |
# | |  | |_   _| | __ _ _ __ | |__     / / (_) |  / /
# | |  | | | | | |/ _  |  _ \|___ \   / / \__  | / /
# | |__| | |_| | | (_| | | | |___) | / /    / / / /
# |_____/ \__  |_|\__|_|_| |_|____/ /_/    /_/ /_/
#          __/ |
#         |___/

import requests
import json
import socket
import hashlib
import os
import sys

class ScratchUserSession:
    SERVER = 'scratch.mit.edu'
    API_SERVER = 'api.scratch.mit.edu'
    PROJECTS_SERVER = 'projects.scratch.mit.edu'
    ASSETS_SERVER = 'assets.scratch.mit.edu'
    CDN_SERVER = 'cdn.scratch.mit.edu'
    CLOUD = 'cloud.scratch.mit.edu'
    CLOUD_PORT = 531
    def __init__(self, username, password, remember_password=False):
        self.lib.utils.request = self._rcallarg
        self.lib.set.username = username
        self.lib.set.password = None
        self.lib.set.password_remembered = remember_password
        if remember_password:
            self.lib.set.password = password
        self.lib.utils.session = requests.session()

        self.tools.verify_session = self._tools_verifySession
        self.tools.update = self._tools_update
        self.tools.reload_session = self._tools_reload_session

        self.projects.get = self._projects_getProject
        self.projects.set = self._projects_setProject
        self.projects.comment = self._projects_comment
        self.projects.get_meta = self._projects_get_meta
        self.projects.get_remix_data = self._projects_get_remixtree

        self.backpack.get = self._backpack_getBackpack
        self.backpack.set = self._backpack_setBackpack

        self.userpage.set_bio = self._userpage_setBio
        self.userpage.set_status = self._userpage_setStatus
        self.userpage.toggle_comments = self._userpage_toggleComments

        self.users.follow = self._users_follow
        self.users.unfollow = self._users_unfollow
        self.users.get_message_count = self._users_get_message_count
        self.users.comment = self._users_comment

        self.studios.comment = self._studios_comment
        self.studios.get_meta = self._studios_get_meta

        self.cloud.set_var = self._cloud_setvar
        self.cloud.create_var = self._cloud_makevar
        self.cloud.get_var = self._cloud_getvar
        self.cloud.get_vars = self._cloud_getvars

        self.HEADERS = {'X-Requested-With': 'XMLHttpRequest', 'Referer':'https://scratch.mit.edu/'}
        self.lib.utils.request(path='/csrf_token/', update=False)
        self.HEADERS['Cookie'] = 'scratchcsrftoken=' + self.lib.utils.session.cookies.get('scratchcsrftoken') + '; scratchlanguage=en'
        self.HEADERS['X-CSRFToken'] = self.lib.utils.session.cookies.get('scratchcsrftoken')
        self.lib.utils.request(path='/login/', method='post', update=False, payload=json.dumps({'username': username, 'password': password, 'csrftoken':self.lib.utils.session.cookies.get('scratchcsrftoken'), 'csrfmiddlewaretoken':self.lib.utils.session.cookies.get('scratchcsrftoken'),'captcha_challenge':'','captcha_response':'','embed_captcha':False,'timezone':'America/New_York'}))
        self.tools.update()
    def _projects_getProject(self, projectId):
        return self.lib.utils.request(path='/internalapi/project/' + projectId + '/get/', server=self.PROJECTS_SERVER).json()
    def _projects_setProject(self, projectId, payload):
        return self.lib.utils.request(server=self.PROJECTS_SERVER, path='/internalapi/project/' + projectId + '/set/', payload=json.dumps(payload), method='post')
    def _projects_get_meta(self, projid):
        return self.lib.utils.request(path='/api/v1/project/' + str(projid) + '/?format=json').json()
    def _projects_get_remixtree(self, projid):
        return self.lib.utils.request(path='/projects/' + str(projid) + '/remixtree/bare/').json()
    def _tools_verifySession(self):
        return self.lib.utils.request(path='/messages/ajax/get-message-count/', port=None).status_code == 200
    def _tools_reload_session(self, password=None, remember_password=None):
        if remember_password == None:
            remember_password = self.lib.set.password_remembered
        if (password == None) and (not self.lib.set.password_remembered):
            raise AttributeError('Password not stored in class (use ScratchUserSesssion(\'User\', \'Password\', remember_password=True) to remember password, or supply your password in ScratchUserSession.tools.reload_session())')
        if password == None:
            password = self.lib.set.password
        self.__init__(self.lib.set.username, password, remember_password=remember_password)
    def _backpack_getBackpack(self):
        return self.lib.utils.request(path='/internalapi/backpack/' + self.lib.set.username + '/get/').json()
    def _backpack_setBackpack(self, payload):
        return self.lib.utils.request(server=self.CDN_SERVER, path='/internalapi/backpack/' + self.lib.set.username + '/set/', method="post", payload=payload)
    def _userpage_setStatus(self, payload):
        p2 = self.lib.utils.request(path='/site-api/users/all/' + self.lib.set.username).json()
        p = {}
        for i in p2:
            if i in ['comments_allowed', 'id', 'status', 'thumbnail_url', 'userId', 'username']:
                p[i] = p2[i]
        p['status'] = payload
        return self.lib.utils.request(path='/site-api/users/all/' + self.lib.set.username, method="put", payload=json.dumps(p))
    def _userpage_toggleComments(self):
        return self.lib.utils.request(path='/site-api/comments/user/' + self.lib.set.username + '/toggle-comments/', method="put", payload=json.dumps(p))
    def _userpage_setBio(self, payload):
        p2 = self.lib.utils.request(path='/site-api/users/all/' + self.lib.set.username).json()
        p = {}
        for i in p2:
            if i in ['comments_allowed', 'id', 'bio', 'thumbnail_url', 'userId', 'username']:
                p[i] = p2[i]
        p['bio'] = payload
        return self.lib.utils.request(path='/site-api/users/all/' + self.lib.set.username, method="put", payload=json.dumps(p))
    def _users_get_meta(self, usr):
        return self.lib.utils.request(path='/users/' + usr, server=self.API_SERVER).json()
    def _users_follow(self, usr):
        return self.lib.utils.request(path='/site-api/users/followers/' + usr + '/add/?usernames=' + self.lib.set.username, method='PUT')
    def _users_unfollow(self, usr):
        return self.lib.utils.request(path='/site-api/users/followers/' + usr + '/remove/?usernames=' + self.lib.set.username, method='PUT')
    def _users_comment(self, user, comment):
        return self.lib.utils.request(path='/site-api/comments/user/' + user + '/add/', method='POST', payload=json.dumps({"content":comment,"parent_id":'',"commentee_id":''}))
    def _studios_comment(self, studioid, comment):
        return self.lib.utils.request(path='/site-api/comments/gallery/' + str(studioid) + '/add/', method='POST', payload=json.dumps({"content":comment,"parent_id":'',"commentee_id":''}))
    def _studios_get_meta(self, studioid):
        return self.lib.utils.request(path='/site-api/galleries/all/' + str(studioid)).json()
    def _studios_invite(self, studioid, user):
        return self.lib.utils.request(path='/site-api/users/curators-in/' + str(studioid) + '/invite_curator/?usernames=' + user, method='PUT')
    def _projects_comment(self, projid, comment):
        return self.lib.utils.request(path='/site-api/comments/project/' + str(projid) + '/add/', method='POST', payload=json.dumps({"content":comment,"parent_id":'',"commentee_id":''}))
    def _cloud_setvar(self, var, value, projId):
        cloudToken = self.lib.utils.request(method='GET', path='/projects/' + str(projId) + '/cloud-data.js').text.rsplit('\n')[-28].replace(' ', '')[13:49]
        bc = hashlib.md5()
        bc.update(cloudToken.encode())
        r = self.lib.utils.request(method='POST', path='/varserver', payload=json.dumps({"token2": bc.hexdigest(), "project_id": str(projId), "value": str(value), "method": "set", "token": cloudToken, "user": self.lib.set.username, "name": '☁ ' + var}))
        return r
    def _cloud_makevar(self, var, value, projId):
        cloudToken = s.lib.utils.request(method='GET', path='/projects/' + str(projId) + '/cloud-data.js').text.rsplit('\n')[-28].replace(' ', '')[13:49]
        bc = hashlib.md5()
        bc.update(cloudToken.encode())
        r = self.lib.utils.request(method='POST', path='/varserver', payload=json.dumps({"token2": bc.hexdigest(), "project_id": str(projId), "value": str(value), "method": "create", "token": cloudToken, "user": self.lib.set.username, "name": '☁ ' + var}))
    def _cloud_getvar(self, var, projId):
        dt = self.lib.utils.request(path='/varserver/' + str(projId)).json()['variables']
        return dt[[x['name']=='☁'+chr(32)+var for x in dt].index(True)]['value']
    def _cloud_getvars(self, projId):
        dt = self.lib.utils.request(path='/varserver/' + str(projId)).json()['variables']
        vardict = {}
        for x in dt:
          xn = x['name']
          if xn.startswith('☁'+chr(32)):
            vardict[xn[2:]] = x['value']
          else:
            vardict[xn] = x['value']
        return vardict
    def _cloud_get_cmd(self, var, projId, value):
        cloudToken = s.lib.utils.request(method='GET', path='/projects/' + str(projId) + '/cloud-data.js').text.rsplit('\n')[-28].replace(' ', '')[13:49]
        bc = hashlib.md5()
        bc.update(cloudToken.encode())
        return {"token2": bc.hexdigest(), "project_id": str(projId), "value": str(value), "method": "create", "token": cloudToken, "user": self.lib.set.username, "name": '☁ ' + var}
    def _tools_update(self):
        self.lib.set.csrf_token = self.lib.utils.session.cookies.get('scratchcsrftoken')
        self.lib.set.sessions_id = self.lib.utils.session.cookies.get('scratchsessionsid')
        self.HEADERS['Cookie'] = 'scratchcsrftoken=' + self.lib.utils.session.cookies.get_dict()['scratchcsrftoken'] + '; scratchsessionsid=' + self.lib.utils.session.cookies.get('scratchsessionsid') + '; scratchlanguage=en'
        self.HEADERS['X-CSRFToken'] = self.lib.utils.session.cookies.get('scratchcsrftoken')
    def _assets_get(self, md5):
        return self.lib.utils.request(path='/internalapi/asset/' + md5 + '/get/', server=self.ASSETS_SERVER).content
    def _assets_set(self, md5, content, content_type=None):
        if not content_type:
            if os.path.splitext(md5)[-1] == '.png':
                content_type = 'image/png'
            elif os.path.splitext(md5)[-1] == '.svg':
                content_type = 'image/svg+xml'
            elif os.path.splitext(md5)[-1] == '.wav':
                content_type = 'audio/wav'
            else:
                content_type = 'text/plain'
        headers = {'Content-Length':str(len(content)),
'Origin':'https://cdn.scratch.mit.edu',
'Content-Type':content_type,
'Referer':'https://cdn.scratch.mit.edu/scratchr2/static/__cc77646ad8a4b266f015616addd66756__/Scratch.swf'}
        return self.lib.utils.request(path='/internalapi/asset/' + md5 + '/set/', method='POST', server=self.ASSETS_SERVER, payload=content)
    def _users_get_message_count(self, user=None):
        if user == None:
            user = self.lib.set.username
        return self.lib.utils.request('/proxy/users/' + user + '/activity/count', server=self.API_SERVER).json()['msg_count']
    def _rcallarg(self, **options):
        headers = {}
        for x in self.HEADERS:
            headers[x] = self.HEADERS[x]
        method = "get"
        server = self.SERVER
        port = ''
        update = True
        retry = 3
        if 'method' in options:
            method = options['method']
        if 'server' in options:
            server = options['server']
        if 'payload' in options:
            headers['Content-Length'] = len(str(options['payload']))
        if 'port' in options:
            if options['port'] == None:
                port = ''
            else:
                port = ':' + str(options['port'])
        if 'update' in options:
            if options['update'] == True:
                self.tools.update()
            else:
                update = False
        else:
            self.tools.update()
        if 'headers' in options:
            headers.update(options['headers'])
        if 'retry' in options:
            retry = options['retry']
        server = 'https://' + server
        def request():
            if 'payload' in options:
                return getattr(self.lib.utils.session, method.lower())(server + port + options['path'], data=options['payload'], headers=headers)
            else:
                return getattr(self.lib.utils.session, method.lower())(server + port + options['path'], headers=headers)
        success = False
        for x in range(0, retry):
            try:
                r = request()
            except requests.exceptions.BaseHTTPError:
                continue
            except AttributeError:
                raise ValueError('Invalid HTTP method')
            else:
                success = True
                break
        if not success:
            raise ConnectionError('Connection failed on all ' + str(retry) + ' attempts')
        if update:
            self.tools.update()
        return r
    class lib:
        class set: pass
        class utils: pass
    class tools: pass
    class projects: pass
    class backpack: pass
    class userpage: pass
    class users: pass
    class studios: pass
    class cloud: pass


class CloudSession:
    def __init__(self, projectId, session):
        if type(session) == ScratchUserSession:
            self._scratch = session
        else:
            self._scratch = ScratchUserSession(session[0], session[1])
        self._user = self._scratch.lib.set.username
        self._projectId = projectId
        self._cloudId = self._scratch.lib.set.sessions_id
        self._token = self._scratch.lib.utils.request(method='GET', path='/projects/' + str(self._projectId) + '/cloud-data.js').text.rsplit('\n')[-28].replace(' ', '')[13:49]
        md5 = hashlib.md5()
        md5.update(self._cloudId.encode())
        self._rollover = []
        self._md5token = md5.hexdigest()
        self._connection = socket.create_connection((ScratchUserSession.CLOUD, ScratchUserSession.CLOUD_PORT))
        self._send('handshake', {})
    def _send(self, method, options):
        obj = {
            'token': self._token,
            'token2': self._md5token,
            'user': self._user,
            'project_id': str(self._projectId),
            'method': method
            }
        obj.update(options)
        ob = (json.dumps(obj) + '\r\n').encode('utf-8')
        self._connection.send(ob)
        md5 = hashlib.md5()
        md5.update(self._md5token.encode())
        self._md5token = md5.hexdigest()

    def set_var(self, name, value):
        self._send('set', {'name': '☁ ' + name, 'value': value})

    def create_var(self, name, value=None):
        if value == None:
            value = 0
        self._send('create', {'name': '☁ ' + name, 'value':value})

    def rename_var(self, oldname, newname):
        self._send('rename', {'name': '☁ ' + oldname, 'new_name': '☁ ' + newname})

    def delete_var(self, name):
        self._send('delete', {'name':'☁ ' + name})

    def get_var(self, name):
        return self._scratch.cloud.get_var(name,self._projectId)

    def get_vars(self):
        return self._scratch.cloud.get_vars(self._projectId)

    def get_updates(self, timeout, maxCount=10):
        count = 0
        updates = []  # keep a dict of all name+value pairs received
        self._connection.settimeout(timeout)  # recv will wait for given time
        while count<maxCount:
          data = ''.encode('utf-8')  # start off blank
          while True:
            try:  # keep concatenating receives (until ended with \n)
              data = data + self._connection.recv(4096)  # raises exception if no data by timeout
              if data[-1]==10:  break  # get out if we found terminating \n
              self._connection.settimeout(0.1)  # allow time for more data
            except:  # or until recv throws exception 'cos there's no data
              break
          if not data:  break  # get out if nothing received
          self._connection.settimeout(0.01)  # allow quick check for more data
          if data[0]==123:  # starts with left brace, so don't prepend rollover
            self._rollover = []  # ...though will this rollover thing ever really be necessary?
          data = self._rollover + data.decode('utf-8').split('\n')  # split up multiple updates
          if data[-1]:  # last line was incomplete, so roll it over...
            print('Warning: last line of data incomplete?! '+data[-1].encode('utf-8'))  # FYI for now...
            self._rollover = [data[-1]]  # put it into rollover for next receive
          else:
            self._rollover = []
          data = data[:-1]  # never need last line - it's either blank or it's rolled over
          for line in data:
            if line:  # ignore blank lines (shouldn't get any?)
              try:
                line = json.loads(line)  # try to parse this entry
                name = line['name']  # try to extract var name
                value = str(line['value'])  # should be string anyway?
                if name.startswith('☁ '):
                  updates.append((name[2:], value))  # avoid leading cloud+space chars
                else:
                  updates.append((name, value))  # probably never happens?
                count = count + 1  # count how many updates we've successfully parsed
              except:  # just ignore data if we can't get 'name'+'value' from it
                continue  # get next entry, or go back to receive more
        self._connection.settimeout(None)  # reset timeout to default
        return updates
    def get_new_values(self, timeout, max_values=10):
        nv = {}
        for x in self.get_updates(timeout, max_values):
            nv[x[0]] = x[1]
        return nv
