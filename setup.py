from distutils.core import setup

setup(
    name='angr-utils',
    version='0.1.0',
    packages=['angrutils', 'angrutils.vis', 'angrutils.vis.angr', 'angrutils.vis.angr.x86'],
    install_requires=[
        'pydot',
        'networkx',
        'angr',
        'claripy',
        'simuvex'
    ],
    description='Various utilities for angr binary analysis framework',
    url='https://github.com/axt/angr-utils',
)
