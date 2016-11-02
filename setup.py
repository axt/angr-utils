from distutils.core import setup

setup(
    name='angr-utils',
    version='0.2.2',
    packages=['angrutils'],
    install_requires=[
        'pydot',
        'networkx',
        'angr',
        'claripy',
        'simuvex',
	'bingraphvis'
    ],
    description='Various utilities for angr binary analysis framework',
    url='https://github.com/axt/angr-utils',
)
