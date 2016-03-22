#!python3
# ScratchAPI 1.0
# Written by Dylan5797 [https://dylan4.com]
#  _____        _             _____ ______ ___ ______
# |  __ \      | |           | ____|____  / _ \____  |
# | |  | |_   _| | __ _ _ __ | |__     / / (_) |  / /
# | |  | | | | | |/ _  |  _ \|___ \   / / \__  | / /
# | |__| | |_| | | (_| | | | |___) | / /    / / / /
# |_____/ \__  |_|\__|_|_| |_|____/ /_/    /_/ /_/
#          __/ |
#         |___/

import requests as _requests
import json as _json
import socket as _socket
import hashlib as _hashlib
import os as _os

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
        self.lib.utils.session = _requests.session()

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
        self.lib.utils.request(path='/login/', method='post', update=False, payload=_json.dumps({'username': username, 'password': password, 'csrftoken':self.lib.utils.session.cookies.get('scratchcsrftoken'), 'csrfmiddlewaretoken':self.lib.utils.session.cookies.get('scratchcsrftoken'),'captcha_challenge':'','captcha_response':'','embed_captcha':False,'timezone':'America/New_York'}))
        self.tools.update()
    def _projects_getProject(self, projectId):
        return self.lib.utils.request(path='/internalapi/project/' + projectId + '/get/', server=self.PROJECTS_SERVER).json()
    def _projects_setProject(self, projectId, payload):
        return self.lib.utils.request(server=self.PROJECTS_SERVER, path='/internalapi/project/' + projectId + '/set/', payload=_json.dumps(payload), method='post')
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
        return self.lib.utils.request(path='/site-api/users/all/' + self.lib.set.username, method="put", payload=_json.dumps(p))
    def _userpage_toggleComments(self):
        return self.lib.utils.request(path='/site-api/comments/user/' + self.lib.set.username + '/toggle-comments/', method="put", payload=_json.dumps(p))
    def _userpage_setBio(self, payload):
        p2 = self.lib.utils.request(path='/site-api/users/all/' + self.lib.set.username).json()
        p = {}
        for i in p2:
            if i in ['comments_allowed', 'id', 'bio', 'thumbnail_url', 'userId', 'username']:
                p[i] = p2[i]
        p['bio'] = payload
        return self.lib.utils.request(path='/site-api/users/all/' + self.lib.set.username, method="put", payload=_json.dumps(p))
    def _users_get_meta(self, usr):
        return self.lib.utils.request(path='/users/' + usr, server=self.API_SERVER).json()
    def _users_follow(self, usr):
        return self.lib.utils.request(path='/site-api/users/followers/' + usr + '/add/?usernames=' + self.lib.set.username, method='PUT')
    def _users_unfollow(self, usr):
        return self.lib.utils.request(path='/site-api/users/followers/' + usr + '/remove/?usernames=' + self.lib.set.username, method='PUT')
    def _users_comment(self, user, comment):
        return self.lib.utils.request(path='/site-api/comments/user/' + user + '/add/', method='POST', payload=_json.dumps({"content":comment,"parent_id":'',"commentee_id":''}))
    def _studios_comment(self, studioid, comment):
        return self.lib.utils.request(path='/site-api/comments/gallery/' + str(studioid) + '/add/', method='POST', payload=_json.dumps({"content":comment,"parent_id":'',"commentee_id":''}))
    def _studios_get_meta(self, studioid):
        return self.lib.utils.request(path='/site-api/galleries/all/' + str(studioid)).json()
    def _studios_invite(self, studioid, user):
        return self.lib.utils.request(path='/site-api/users/curators-in/' + str(studioid) + '/invite_curator/?usernames=' + user, method='PUT')
    def _projects_comment(self, projid, comment):
        return self.lib.utils.request(path='/site-api/comments/project/' + str(projid) + '/add/', method='POST', payload=_json.dumps({"content":comment,"parent_id":'',"commentee_id":''}))
    def _cloud_setvar(self, var, value, projId):
        cloudToken = self.lib.utils.request(method='GET', path='/projects/' + str(projId) + '/cloud-data.js').text.rsplit('\n')[-28].replace(' ', '')[13:49]
        bc = _hashlib.md5()
        bc.update(cloudToken.encode())
        r = self.lib.utils.request(method='POST', path='/varserver', payload=_json.dumps({"token2": bc.hexdigest(), "project_id": str(projId), "value": str(value), "method": "set", "token": cloudToken, "user": self.lib.set.username, "name": '☁ ' + var}))
        return r
    def _cloud_makevar(self, var, value, projId):
        cloudToken = s.lib.utils.request(method='GET', path='/projects/' + str(projId) + '/cloud-data.js').text.rsplit('\n')[-28].replace(' ', '')[13:49]
        bc = _hashlib.md5()
        bc.update(cloudToken.encode())
        r = self.lib.utils.request(method='POST', path='/varserver', payload=_json.dumps({"token2": bc.hexdigest(), "project_id": str(projId), "value": str(value), "method": "create", "token": cloudToken, "user": self.lib.set.username, "name": '☁ ' + var}))
    def _cloud_getvar(self, var, projId):
        dt = self.lib.utils.request(path='/varserver/' + str(projId)).json()['variables']
        return dt[[x['name'] == '☁ ' + var for x in dt].index(True)]['value']
    def _cloud_getvars(self, projId):
        dt = self.lib.utils.request(path='/varserver/' + str(projId)).json()['variables']
        vardict = {}
        for x in dt:
          xn = x['name']
          if xn.startswith('☁ '):
            vardict[xn[2:]] = x['value']
          else:
            vardict[xn] = x['value']
        return vardict
    def _cloud_get_cmd(self, var, projId, value):
        cloudToken = s.lib.utils.request(method='GET', path='/projects/' + str(projId) + '/cloud-data.js').text.rsplit('\n')[-28].replace(' ', '')[13:49]
        bc = _hashlib.md5()
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
            except _requests.exceptions.BaseHTTPError:
                continue
            except AttributeError:
                raise ValueError('Unknown HTTP method')
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
        md5 = _hashlib.md5()
        md5.update(self._cloudId.encode())
        self._rollover = []
        self._md5token = md5.hexdigest()
        self._connection = _socket.create_connection((self._scratch.CLOUD, self._scratch.CLOUD_PORT))
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
        ob = (_json.dumps(obj) + '\r\n').encode('utf-8')
        self._connection.send(ob)
        md5 = _hashlib.md5()
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
        updates = []
        self._connection.settimeout(timeout)
        while count < maxCount:
            data = ''.encode('utf-8')
            while True:
                try:
                    data = data + self._connection.recv(4096)
                    if data[-1] == 10:
                        break
                    self._connection.settimeout(0.1)
                except:
                    break
            if not data:
                break
            self._connection.settimeout(0.01)
            if data[0] == 123:
                self._rollover = []
            data = self._rollover + data.decode('utf-8').split('\n')
            if data[-1]:
                self._rollover = [data[-1]]
            else:
                self._rollover = []
            data = data[:-1]
            for line in data:
                if line:
                    try:
                        line = _json.loads(line)
                        name = line['name']
                        value = str(line['value'])
                        if name.startswith('☁ '):
                            updates.append((name[2:], value))
                        else:
                            updates.append((name, value))
                        count = count + 1
                    except:
                        continue
        self._connection.settimeout(None)
        return updates

    def get_new_values(self, timeout, max_values=10):
        nv = {}
        for x in self.get_updates(timeout, max_values):
            nv[x[0]] = x[1]
        return nv
