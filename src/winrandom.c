/*
winrandom.c

Python interface to Windows Cryptographic API CryptGenRandom()

Pawel Krawczyk <pawel.krawczyk@hush.com>
*/

#include <Python.h>

PyObject *exception = NULL;

#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <math.h>
#include <stdio.h>
#include <ctype.h>

/* This function implements B.5.1.1 Simple Discard Method from NIST SP800-90
 * http://csrc.nist.gov/publications/nistpubs/800-90A/SP800-90A.pdf
 * Simple discard method is used to produce random LONG until it fits in 0..MAX range
 */
static PyObject *winrandom_range(PyObject *self, PyObject *args) {
	HCRYPTPROV hProv;
	unsigned long rand_out;
	static unsigned long iContinousRndTest = 0L;
	unsigned long upperLimitBytes;
	double upperLimitBits; /* because ceil() returns DOUBLE */
	int rand_max; // unsigned so we can catch negative arguments
	int ok;

	ok = PyArg_ParseTuple(args, "I", &rand_max);
	if(!ok) {
		PyErr_SetObject(exception, PyExc_ValueError);
		return NULL;
	}
	if(rand_max <= 1) {
		// rand_max needs to be >1 because for 1 the upperLimitBits will be 0 and no random number
		// will be returned; the logic of this function is that 0 <= n <= rand_max-1
		PyErr_SetObject(exception, PyExc_ValueError);
		return NULL;
	}

	/* try stronger crypto provider first */
	ok = CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
	if(!ok) {
		ok = CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
		if(!ok) {
			PyErr_SetString(exception, "Unable to acquire Windows random number generator");
			return NULL;
		}
	}

	// how many bits are needed to store max
	// need to use log(2) as log() is base e
	upperLimitBits = ceil(log(rand_max-1) / log(2));
	upperLimitBytes = (long) ceil(upperLimitBits/8); // how many bytes

	/* Fetch random bytes until it's lower than desired range */
	while(1) {
		long retVal;
		rand_out = 0L; /* overwrite whatever was there */
		retVal = CryptGenRandom(hProv, upperLimitBytes, (BYTE *) &rand_out);
		if(!retVal) {
			PyErr_SetString(exception, "Unable to fetch random data from Windows");
			return NULL;
		}
		/* FIPS 140-2 p. 44 Continuous random number generator test */
		/* Check if previous number wasn't the same as current */
		if(upperLimitBits > 15 && rand_out == iContinousRndTest) {
				PyErr_SetString(exception, "Continuous random number generator test failed");
				return NULL;
			}
		iContinousRndTest = rand_out; /* preserve this value for continuous test */
		if(rand_out < (unsigned int) rand_max) break; // found!
	}

	CryptReleaseContext(hProv, 0);
	return Py_BuildValue("k", rand_out);
}

static PyObject *winrandom_bytes(PyObject *self, PyObject *args)
{
	HCRYPTPROV hProv;
	unsigned int num_bytes;
	unsigned char *s;
	int ok;

	ok = PyArg_ParseTuple(args, "I", &num_bytes);
	if(!ok) {
		PyErr_SetObject(exception, PyExc_ValueError);
		return NULL;
	}

	s = malloc(num_bytes);
	if(s == NULL) {
		PyErr_SetObject(exception, PyExc_MemoryError);
		return NULL;
	}

	// CryptoAPI
	/* try stronger crypto provider first */
		ok = CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
		if(!ok) {
			ok = CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
			if(!ok) {
				PyErr_SetString(exception, "Unable to acquire Windows random number generator");
				return NULL;
		}
	}

	ok = CryptGenRandom(hProv, (DWORD) num_bytes, (BYTE *) s);
	if(!ok) {
				PyErr_SetString(exception, "Unable to fetch random data from Windows");
				return NULL;
			}

	return Py_BuildValue("s#", s, num_bytes);
}

static PyObject *winrandom_long(PyObject *self, PyObject *args)
{
	HCRYPTPROV hProv;
	unsigned long pbRandomData;
	int ok;

	/* try stronger crypto provider first */
			ok = CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
			if(!ok) {
				ok = CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
				if(!ok) {
					PyErr_SetString(exception, "Unable to acquire Windows random number generator");
					return NULL;
		}
	}

	//  Generate eight bytes of random data into pbRandomData.
	ok = CryptGenRandom(hProv, (DWORD) sizeof(pbRandomData), 
			(BYTE *) &pbRandomData);
	if(!ok) {
			PyErr_SetString(exception, "Unable to fetch random data from Windows");
			return NULL;
	}

	return Py_BuildValue("k", pbRandomData);
}

#define LONG_TEXT 	"winrandom.long() - get cryptographically strong pseudo-random long integer."
#define BYTES_TEXT 	"winrandom.bytes(N) - get N cryptographically strong pseudo-random bytes."
#define RANGE_TEXT 	"winrandom.range(MAX) - get cryptographically strong pseudo-random integer N that is 0 <= N < MAX." \
					"Note that the returned is between 0 and MAX-1 inclusive. To cycle between 0 and 1 you need range(2)."

static PyMethodDef WinrandomMethods[] = {
	{"long", winrandom_long, METH_VARARGS, LONG_TEXT },
	{"bytes", winrandom_bytes, METH_VARARGS, BYTES_TEXT },
	{"range", winrandom_range, METH_VARARGS, RANGE_TEXT },
	{NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC
initwinrandom(void) {
	PyObject *m;

	 m = Py_InitModule("winrandom", WinrandomMethods);
	 if (m == NULL)
		return;

	 exception = PyErr_NewException("winrandom.error", NULL, NULL);
	 Py_INCREF(exception);
	 PyModule_AddObject(m, "error", exception);

	 //PyDict_SetItemString(d, "error", exception);
}
