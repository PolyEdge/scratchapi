from setuptools import setup, find_packages
# To use a consistent encoding
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='scratchapi',

    version='1.0.0',

    description='ScratchAPI is a Scratch API interface written in Python',
    long_description=long_description,

    url='https://github.com/Dylan5797/ScratchAPI',

    author='Dylan5797',
    author_email='None@fake.com',

    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',

        'Programming Language :: Python :: 3',
    ],

    keywords='scratch api cloud',

    py_modules=["scratchapi"],

    install_requires=['requests'],

)
