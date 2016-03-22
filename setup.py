from distutils.core import setup

setup(
    name='angr-utils',
    version='0.0.2',
    packages=['angrutils'],
    install_requires=[
        'pydot',
    ],
    description='Various utilities for angr binary analysis framework',
    url='https://github.com/axt/angr-utils',
)
