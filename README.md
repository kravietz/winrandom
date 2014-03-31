# winrandom

This module gives direct access to Windows Cryptographic API CryptGetRandom() function, which is cryptographically strong pseudo-random number generator (PRNG) on Windows:

* **long()** returns random unsigned _long_ integer

		>>> import winrandom
		>>> winrandom.long()
		2141228967

* **bytes(_n_)** returns _n_ random bytes

		>>> winrandom.bytes(10)
		"\x1e'^';]\xda\xf0\x91\xba"

* **range(_max_)** returns a random integer _i_ from range 0 to _max_ (0 <= _i_ < _max_). Random data originates from the PRNG but to ensure that the integer is not biased an algorithm from NIST SP800-90 is used (_B.5.1.1 Simple Discard Method_). In addition, in the internal loop a continuous random number generator test is executed (_FIPS 140-2 p. 44_).
 
		>>> winrandom.range(1000)
		706

# History
* 1.0 added winrandom.long(), first published at [IPSec.pl](http://ipsec.pl/winrandom)
* 1.1 added winrandom.bytes(num)
* 1.2 added winrandom.range(max)

# Note
**This module is obsolete since Python 2.4 when [os.urandom](https://docs.python.org/2/library/os.html#os.urandom) was added to provide operating system based randomness on all supported systems.**
