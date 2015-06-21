cryptl: cryptographic C++ template library parameterized by code management
================================================================================

--------------------------------------------------------------------------------
Introduction
--------------------------------------------------------------------------------

The cryptl template library evolved out of [snarkfront], a domain specific
language for zero knowledge proofs. In snarkfront, cryptographic algorithms
appear in two contexts: unmanaged and managed.

The first context, unmanaged, is immediate evaluation. This is the usual sense
of application code. Algorithms "eagerly" calculate an answer.

The second context, managed, is "lazy" for domain specific languages. This is
the usual way a dynamic language works. Algorithms build up structures for
deferred evaluation by a runtime.

I am not aware of other cryptographic libraries that address this situation.
That is, templated implementations parameterized in such a way to be used for
both unmanaged and managed code. It is not a typical applications programming
use case.

Another motivation were growing dependencies between other projects and these
templates. It made sense to package them together as a distinct library to
avoid duplication.

--------------------------------------------------------------------------------
[TOC]

<!---
  NOTE: the file you are reading is in Markdown format, which is is fairly readable
  directly, but can be converted into an HTML file with much nicer formatting.
  To do so, run "make doc" (this requires the python-markdown package) and view
  the resulting file README.html.
-->

--------------------------------------------------------------------------------
Cryptographic algorithms
--------------------------------------------------------------------------------

- [FIPS PUB 180-4]: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256
- [FIPS PUB 197]: AES-128, AES-192, AES-256

--------------------------------------------------------------------------------
Library build instructions
--------------------------------------------------------------------------------

There is nothing to build in the library itself. It is entirely C++ templates.
Applications only need to include the header files.

To install the library:

    $ make install PREFIX=/usr/local

The header files are copied to directory $(PREFIX)/include/cryptl .

--------------------------------------------------------------------------------
NIST [Advanced Encryption Standard Algorithm Validation Suite (AESAVS)]
--------------------------------------------------------------------------------

Download the example [AES Known Answer Test (KAT) Vectors] from NIST:

    $ mkdir AESAVS_testdata
    $ cd AESAVS_testdata
    $ wget http://csrc.nist.gov/groups/STM/cavp/documents/aes/KAT_AES.zip
    $ unzip KAT_AES.zip
    $ cd ..

Build the AESAVS binary:

    $ make AESAVS

Run the validation tests:

    $ ./AESAVS.sh AESAVS_testdata

--------------------------------------------------------------------------------
NIST [Secure Hash Algorithm Validation System (SHAVS)]
--------------------------------------------------------------------------------

Download the example [Test Vectors for Hashing Byte-Oriented Messages] from NIST:

    $ mkdir SHAVS_testdata
    $ cd SHAVS_testdata
    $ wget http://csrc.nist.gov/groups/STM/cavp/documents/shs/shabytetestvectors.zip
    $ unzip shabytetestvectors.zip
    $ cd ..

Build the SHAVS binary:

    $ make SHAVS

Run the validation tests:

    $ ./SHAVS.sh SHAVS_testdata

--------------------------------------------------------------------------------
References
--------------------------------------------------------------------------------

[snarkfront]: https://github.com/jancarlsson/snarkfront

[FIPS PUB 180-4]: http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf

[FIPS PUB 197]: https://csrc.nist.gov/publications/fips/fips197/fips-197.pdf

[Advanced Encryption Standard Algorithm Validation Suite (AESAVS)]: http://csrc.nist.gov/groups/STM/cavp/documents/aes/AESAVS.pdf

[AES Known Answer Test (KAT) Vectors]: http://csrc.nist.gov/groups/STM/cavp/documents/aes/KAT_AES.zip

[Secure Hash Algorithm Validation System (SHAVS)]: http://csrc.nist.gov/groups/STM/cavp/documents/shs/SHAVS.pdf

[Test Vectors for Hashing Byte-Oriented Messages]: http://csrc.nist.gov/groups/STM/cavp/documents/shs/shabytetestvectors.zip
