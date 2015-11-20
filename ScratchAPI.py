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

class ScratchUserSession:
    SERVER = 'scratch.mit.edu'
    PROJECTS_SERVER = 'projects.scratch.mit.edu'
    ASSETS_SERVER = 'assets.scratch.mit.edu'
    CDN_SERVER = 'cdn.scratch.mit.edu'
    CLOUD = 'cloud.scratch.mit.edu'
    CLOUD_PORT = 531
    def __init__(self, username, password): # Much self lol
        self.lib.utils.request = self._rcallarg
        self.lib.set.username = username
        self.lib.utils.session = requests.session()
        self.tools.verifySession = self._tools_verifySession
        self.projects.get = self._projects_getProject
        self.projects.set = self._projects_setProject
        self.backpack.get = self._backpack_getBackpack
        self.backpack.set = self._backpack_setBackpack
        self.userpage.setBio = self._userpage_setBio
        self.userpage.setStatus = self._userpage_setStatus
        self.users.follow = self._users_follow
        self.users.unfollow = self._users_unfollow
        self.HEADERS = {'X-Requested-With': 'XMLHttpRequest', 'Referer':'https://scratch.mit.edu/'}
        self.lib.utils.request(path='/csrf_token/')
        self.HEADERS['Cookie'] = 'scratchcsrftoken=' + self.lib.utils.session.cookies.get('scratchcsrftoken') + '; scratchlanguage=en'
        self.HEADERS['X-CSRFToken'] = self.lib.utils.session.cookies.get('scratchcsrftoken')
        self.lib.utils.request(path='/login/', method='post', payload=json.dumps({'username': username, 'password': password, 'csrftoken':self.lib.utils.session.cookies.get('scratchcsrftoken'), 'csrfmiddlewaretoken':self.lib.utils.session.cookies.get('scratchcsrftoken'),'captcha_challenge':'','captcha_response':'','embed_captcha':False,'timezone':'America/New_York'}))
        self.HEADERS['Cookie'] = 'scratchcsrftoken=' + self.lib.utils.session.cookies.get_dict()['scratchcsrftoken'] + ';scratchsessionsid=' + self.lib.utils.session.cookies.get('scratchsessionsid') + '; scratchlanguage=en'
        self.HEADERS['X-CSRFToken'] = self.lib.utils.session.cookies.get('scratchcsrftoken')
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
    def _users_follow(usr):
        return self.lib.utils.request(path='/site-api/users/followers/' + usr + '/add/?usernames=' + self.lib.set.username)
    def _users_unfollow(usr):
        return self.lib.utils.request(path='/site-api/users/followers/' + usr + '/remove/?usernames=' + self.lib.set.username)
    def _rcallarg(self, **options):
        headers = {}
        for x in self.HEADERS:
            headers[x] = self.HEADERS[x]
        method = "get"
        server = ScratchUserSession.SERVER
        port = ':443'
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
        server = 'https://' + server
        def do():
            if 'payload' in options:
                r = getattr(self.lib.utils.session, method.lower())(server + port + options['path'], data=options['payload'], headers=headers)
            else:
                r = getattr(self.lib.utils.session, method.lower())(server + port + options['path'], headers=headers)
            return r
        for x in range(0, 2): #Try again twice if error
            try:
                r = do()    
            except:
                continue
            else:
                break
        return r
    class lib:
        class set: pass
        class utils: pass
    class tools: pass
    class projects: pass
    class backpack: pass
    class userpage: pass
    class users: pass
