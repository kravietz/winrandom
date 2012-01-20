from distutils.core import setup, Extension

winrandom1 = Extension('winrandom',
	libraries = ['Crypt32'],
	sources = ['src/winrandom.c'])

setup (name = 'winrandom',
	author='Pawel Krawczyk',
	author_email='pawel.krawczyk@hush.com',
	url='http://ipsec.pl/winrandom',
	version = '1.1',
	description = 'Access to Cryptographic API random generator',
	long_description = """
This very simple module gives direct access to Windows Cryptographic
API CryptGetRandom() function.

Example:

>>> import winrandom
>>> print winrandom.long()
2141228967
>>> print repr(winrandom.bytes(10))
<ASCII ENCODED JUNK>

Changelog:
1.0	added winrandom.long()
1.1	added winrandom.bytes(num) returning num random bytes
""",
	license = "Public domain",
	platforms = ["Win32"],
	classifiers = ['Development Status :: 3 - Alpha',
          'License :: Public Domain',
	  'Topic :: Security :: Cryptography',
	  'Programming Language :: C',
          'Intended Audience :: Developers',
          'Operating System :: Microsoft :: Windows'],
	ext_modules = [winrandom1])
