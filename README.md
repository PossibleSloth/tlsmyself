# tlsmyself
This is an experiment to try using the AFL fuzzer to test the TLS handshake functions of GnuTLS.

GnuTLS was compiled and instrumented with AFL's version of the clang compiler
```
CC=afl-clang-fast ./configure --without-p11-kit --disable-non-suiteb-curves --disable-doc --disable-valgrind-tests
```
Compile the TLS handshake tester with the same compiler
```
afl-clang-fast -I/path/to/gnutls/include -L/path/to/gnutls/lib -lgnutls -g -o tester tester.c
```
`tester` will create a TLS server and client and perform a handshake between the two. To avoid networking complications, the two use pipes to pass the messages back and forth. When it's run without arguments, it saves the messages to a folder called `saved`.

When run with a `-c` or `-s` (for "client" or "server") followed by a number N and a filename F, it will run through the handshake but will replace the Nth client or server message with whatever is in the given file. This is how it can be used with the fuzzer.

The server is run with AFL like so:
```
afl-fuzz -i inputs -o findings_dir -t 1000 -m 100000000 -- ./tester -s 1 @@
```
where the folder `inputs` contains the saved server message #1


# Breaking RNG
In order to make the test repeatable and re-used saved samples, I had to break the RNG used by GnuTLS. Breaking the timestamp function could be done within the test app. No change to the GnuTLS souce required. It involved calling `gnutls_global_set_time_function` and passing it a pointer to this:
```
time_t stuck_time()
{
	return 2863311530;
}
```

The TLS handshake also involves random numbers for generating nonces and coming up with random primes for the Diffie Hellman exchange. I rewrote part of the code in gnutls' random.h

### original:
```
inline static int
_gnutls_rnd(gnutls_rnd_level_t level, void *data, size_t len)
{
	int ret;
	if (len > 0) {
		return _gnutls_rnd_ops.rnd(gnutls_rnd_ctx, level, data,
					   len);
	}
	return 0;
}
```
### modified:
```
int broken_rng_seed;

inline static void
broken_rng(void *data, size_t len)
{
	int i;
	memset(data, '\0', len);
	char *d = (char*)data;
	
	broken_rng_seed++;
		
	for (i = 0; i < len; i++) {
		d[i] = (char) ((broken_rng_seed >> (8*i)) & 0xFF);
	}
}

inline static int
_gnutls_rnd(gnutls_rnd_level_t level, void *data, size_t len)
{
	int ret;
	if (len > 0) {
		//ret = _gnutls_rnd_ops.rnd(gnutls_rnd_ctx, level, data,
		//			   len);
		broken_rng(data, len);
		return 0;
	}
	return 0;
}
```
Pretty strange, right? My first thought was to just call `memset` with some constant value on the data instead of calling the rng function, but there was a problem. It turns out some parts of GnuTLS will repeatedly call the rng function until they get a value with some specific properties (e.g. prime number). If rng always returns the same value, chances are you'll get stuck on one of those loops.

