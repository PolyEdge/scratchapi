ScratchAPI

Scratch API Interface

ScratchAPI is a scratch API interface written in Python.

To get started, install it with pip install scratchapi

Logging in

To use the api, you must log in to your scratch account:

  import scratchapi
  scratch = scratchapi.ScratchUserSession('Username', 'password')

Now, you can verify your session to see if you logged in correctly:

  scratch.tools.verify_session()

There are a lot of things you can you when you're logged in!

Take ownership of a new project:

  scratch.lib.utils.request(path='/internalapi/project/new/set/?v=v442&title=Project', server=scratch.PROJECTS_SERVER, method='POST', payload={})

Follow Someone:

  scratch.users.follow('Bob')

Set a cloud variable:

  s.cloud.set_var('Variable', 12345, 4453648)

Credits
The cloud data interface information was acquired from various topics on the Scratch Forums.

TheLogFather helped out with various wrappers and conveniences for cloud data.
