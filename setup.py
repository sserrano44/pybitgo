from distutils.core import setup
setup(
  name = 'bitgo',
  packages = ['bitgo'],
  version = '0.1',
  description = 'alpha version of a bitgo python library',
  author = 'Sebastian Serrano',
  author_email = 'sebastian@bitpagos.com',
  url = 'https://github.com/sserrano44/pybitgo',
  download_url = 'https://github.com/sserrano44/pybitgo/archive/master.tar.gz',
  keywords = ['bitcoin', 'bitgo'], # arbitrary keywords
  classifiers = [],
  install_requires=["pycryptodome", "requests", "pycoin"]
)

