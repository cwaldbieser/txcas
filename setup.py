
from distutils.core import setup

setup(
    url='none',
    author='Matt Haggard',
    author_email='haggardii@gmail.com',
    name='txcas',
    version='0.1',
    packages=[
        'txcas', 'txcas.test',
    ],
    install_requires=[
        'klein',
        'requests',
        'Twisted>=10.1.0',
    ],
)
