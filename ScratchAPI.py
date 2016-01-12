#!python3.4
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

class ScratchUserSession:
    SERVER = 'scratch.mit.edu'
    API_SERVER = 'api.scratch.mit.edu'
    PROJECTS_SERVER = 'projects.scratch.mit.edu'
    ASSETS_SERVER = 'assets.scratch.mit.edu'
    CDN_SERVER = 'cdn.scratch.mit.edu'
    CLOUD = 'cloud.scratch.mit.edu'
    CLOUD_PORT = 531
    def __init__(self, username, password):
        self.lib.utils.request = self._rcallarg
        self.lib.set.username = username
        self.lib.utils.session = requests.session()
        self.tools.verifySession = self._tools_verifySession
        self.tools.update = self._tools_update
        self.projects.get = self._projects_getProject
        self.projects.set = self._projects_setProject
        self.backpack.get = self._backpack_getBackpack
        self.backpack.set = self._backpack_setBackpack
        self.userpage.setBio = self._userpage_setBio
        self.userpage.setStatus = self._userpage_setStatus
        self.users.follow = self._users_follow
        self.users.unfollow = self._users_unfollow
        self.cloud.set_var = self._cloud_setvar
        self.cloud.create_var = self._cloud_makevar
        self.cloud.get_var = self._cloud_getvar
        self.HEADERS = {'X-Requested-With': 'XMLHttpRequest', 'Referer':'https://scratch.mit.edu/'}
        self.lib.utils.request(path='/csrf_token/', update=False)
        self.HEADERS['Cookie'] = 'scratchcsrftoken=' + self.lib.utils.session.cookies.get('scratchcsrftoken') + '; scratchlanguage=en'
        self.HEADERS['X-CSRFToken'] = self.lib.utils.session.cookies.get('scratchcsrftoken')
        self.lib.utils.request(path='/login/', method='post', update=False, payload=json.dumps({'username': username, 'password': password, 'csrftoken':self.lib.utils.session.cookies.get('scratchcsrftoken'), 'csrfmiddlewaretoken':self.lib.utils.session.cookies.get('scratchcsrftoken'),'captcha_challenge':'','captcha_response':'','embed_captcha':False,'timezone':'America/New_York'}))
        self.tools.update()
    def _projects_getProject(self, projectId):
        return self.lib.utils.request(path='/internalapi/project/' + projectId + '/get/', server=ScratchUserSession.PROJECTS_SERVER).json()
    def _projects_setProject(self, projectId, payload):
        return self.lib.utils.request(server=ScratchUserSession.PROJECTS_SERVER, path='/internalapi/project/' + projectId + '/set/', payload=json.dumps(payload), method='post')
    def _tools_verifySession(self):
        return self.lib.utils.request(path='/messages/ajax/get-message-count/', port=None).status_code == 200
    def _backpack_getBackpack(self):
        return self.lib.utils.request(path='/internalapi/backpack/' + self.lib.set.username + '/get/').json()
    def _backpack_setBackpack(self, payload):
        return self.lib.utils.request(server=ScratchUserSession.CDN_SERVER, path='/internalapi/backpack/' + self.lib.set.username + '/set/', method="post", payload=payload)
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
    def _users_follow(self, usr):
        return self.lib.utils.request(path='/site-api/users/followers/' + usr + '/add/?usernames=' + self.lib.set.username)
    def _users_unfollow(self, usr):
        return self.lib.utils.request(path='/site-api/users/followers/' + usr + '/remove/?usernames=' + self.lib.set.username)
    def _users_comment(self, user, comment):
        return self.lib.utils.request(path='/site-api/users/followers/' + usr + '/remove/?usernames=' + self.lib.set.username)
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
    def _rcallarg(self, **options):
        headers = {}
        for x in self.HEADERS:
            headers[x] = self.HEADERS[x]
        method = "get"
        server = ScratchUserSession.SERVER
        port = ''
        if 'method' in options:
            method = options['method']
        if 'server' in options:
            server = options['server']
        if 'headers' in options:
            headers.update(options['headers'])
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
            self.tools.update()
        server = 'https://' + server
        def request():
            if 'payload' in options:
                r = getattr(self.lib.utils.session, method.lower())(server + port + options['path'], data=options['payload'], headers=headers)
            else:
                r = getattr(self.lib.utils.session, method.lower())(server + port + options['path'], headers=headers)
            return r
        for x in range(0, 3):
            try:
                r = request()    
            except:
                r = None
                continue
            else:
                break
        if not r:
            raise ConnectionError('Connection failed on all three attempts')
        if 'update' in options:
            if options['update'] == True:
                self.tools.update()             
        else:
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
    class cloud: pass


class CloudSession:
    def __init__(self, projectId, scratch):
        self.scratch = scratch
        self.user = self.scratch.lib.set.username
        self.projectId = projectId
        self.cloudId = self.scratch.lib.set.sessions_id
        self.token = self.scratch.lib.utils.request(method='GET', path='/projects/' + str(self.projectId) + '/cloud-data.js').text.rsplit('\n')[-28].replace(' ', '')[13:49]
        md5 = hashlib.md5()
        md5.update(self.cloudId.encode())
        self.md5token = md5.hexdigest()
        self.connection = socket.create_connection((ScratchUserSession.CLOUD, ScratchUserSession.CLOUD_PORT))
        self._send('handshake', {})
    def _send(self, method, options):
        obj = {
            'token': self.token,
            'token2': self.md5token,
            'user': self.user,
            'project_id': str(self.projectId),
            'method': method
            }
        obj.update(options)
        ob = (json.dumps(obj) + '\r\n').encode('utf-8')
        self.connection.send(ob)
        md5 = hashlib.md5()
        md5.update(self.md5token.encode())
        self.md5token = md5.hexdigest()
        
    def set_var(self, name, value):
        self._send('set', {'name': '☁ ' + name, 'value': value})

    def create_var(self, name, value):
        self._send('create', {'name': '☁ ' + name, 'value': value})
