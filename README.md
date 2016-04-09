# scratchapi #
scratchapi is a web API interface for [Scratch](https://scratch.mit.edu), written in [Python](https://www.python.org/).

To get started, install it via pip by running `pip install scratchapi`   
Alternatively, you can download this repository and run `python setup.py install` 

## Getting Started ##
To use the api, you must log in to your scratch account:
```python
import scratchapi
scratch = scratchapi.ScratchUserSession('Username', 'password')
```

### After login ###
Now, you can verify your session to see if you logged in correctly:
```python
scratch.tools.verify_session() # Should return True
```
There are a lot of things you can you when you're logged in!

Take ownership of a new project:
```python
scratch.lib.utils.request(path='/internalapi/project/new/set/?v=v442&title=Project', server=scratch.PROJECTS_SERVER, method='POST', payload={})
```

Follow Someone:
```python
scratch.users.follow('Bob')
```

Set a cloud variable:
```python
s.cloud.set_var('Variable', 12345, 4453648)
```

## Documentation ##
I apologize for a lack of documentation at this very moment, some is on the way, and some is already located on scratchapi's [wiki](https://github.com/Dylan5797/scratchapi/wiki).

## Credits ##
Some of the cloud data interface information was acquired from various topics on the [Scratch Forums](https://scratch.mit.edu/discuss).

Certain code snips were based off [scratch-api](https://github.com/trumank/scratch-api), by Truman Kilen.

[TheLogFather](https://github.com/TheLogFather) helped out with various wrappers and conveniences for cloud data.

If you're using scratchapi for your project, I'd appreciate if you would give credit to me and my scratch account, [@Dylan5797](https://scratch.mit.edu/users/Dylan5797/).
