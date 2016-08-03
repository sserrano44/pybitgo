from setuptools import setup

version = "0.1.3"

setup(
    name='bitgo',
    packages=['bitgo'],
    version=version,
    description='alpha version of a bitgo python library',
    author='Sebastian Serrano',
    author_email='sebastian@bitpagos.com',
    entry_points={
        'console_scripts':
            [
                'bitgo = bitgo.cmd:main',
            ]
    },
    url='https://github.com/sserrano44/pybitgo',
    download_url='https://github.com/sserrano44/pybitgo/tarball/%s' % version,
    keywords=['bitcoin', 'bitgo'],
    classifiers=[
        'Programming Language :: Python :: 2.7',
        'Topic :: Internet',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    install_requires=["pycryptodome", "requests", "pycoin"]
)
