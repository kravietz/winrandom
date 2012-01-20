from distutils.core import setup, Extension

winrandom1 = Extension('winrandom',
	libraries=['Crypt32'],
	sources=['src/winrandom.c'])

setup (name='winrandom',
	author='Pawel Krawczyk',
	author_email='pawel.krawczyk@hush.com',
	url='http://ipsec.pl/winrandom',
	version='1.2',
	description='Access to Cryptographic API random generator',
	long_description="""
This module gives direct access to Windows Cryptographic
API CryptGetRandom() function. The range() function
uses B.5.1.1 Simple Discard Method from NIST SP800-90
with FIPS 140-2 p. 44 Continuous random number generator test.

Examples:

>>> import winrandom
>>> print winrandom.long()
2141228967
>>> print repr(winrandom.bytes(10))
<10 random bytes>
>> print winrandom.range(1000)
123

Changelog:
1.0	added winrandom.long()
1.1	added winrandom.bytes(num) returning num random bytes
1.2 added winrandom.range(max) returning random index n where 0 <= n < max
""",
	license="Public domain",
	platforms=["Win32"],
	classifiers=['Classifier: Development Status :: 5 - Production/Stable',
          'License :: Public Domain',
	  'Topic :: Security :: Cryptography',
	  'Programming Language :: C',
	  'Classifier: Programming Language :: Python',
          'Intended Audience :: Developers',
          'Operating System :: Microsoft :: Windows'],
	ext_modules=[winrandom1])
