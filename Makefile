CXX = g++
CXXFLAGS = -O2 -g3 -std=c++11 -I.

RM = rm
LN = ln
AR = ar
RANLIB = ranlib

LIBRARY_HPP = \
	AES.hpp \
	AES_Cipher.hpp \
	AES_InvCipher.hpp \
	AES_InvSBox.hpp \
	AES_KeyExpansion.hpp \
	AES_SBox.hpp \
	ASCII_Hex.hpp \
	BitwiseINT.hpp \
	Bless.hpp \
	CipherModes.hpp \
	DataPusher.hpp \
	Digest.hpp \
	ED25519.hpp \
	ED25519_fe.hpp \
	ED25519_gebase1.hpp \
	ED25519_gebase2.hpp \
	ED25519_gebase3.hpp \
	ED25519_gebase4.hpp \
	ED25519_gebase5.hpp \
	ED25519_ge.hpp \
	ED25519_sc.hpp \
	NS_cryptl.hpp \
	SHA.hpp \
	SHA_1.hpp \
	SHA_224.hpp \
	SHA_256.hpp \
	SHA_384.hpp \
	SHA_512_224.hpp \
	SHA_512_256.hpp \
	SHA_512.hpp

default :
	@echo Build options:
	@echo make AESAVS
	@echo make ED25519_test
	@echo make SHAVS
	@echo make install PREFIX=\<path\>
	@echo make doc
	@echo make clean

README.html : README.md
	markdown_py -f README.html README.md -x toc -x extra --noisy

doc : README.html

CLEAN_FILES = \
	AESAVS \
	ED25519_test \
	SHAVS \
	README.html

clean :
	rm -f *.o $(CLEAN_FILES) cryptl

ifeq ($(PREFIX),)
install :
	$(error Please provide PREFIX, e.g. make install PREFIX=/usr/local)
else
# installing just copies over the template library header files
install :
	mkdir -p $(PREFIX)/include/cryptl
	cp $(LIBRARY_HPP) $(PREFIX)/include/cryptl
endif

# need symbolic link for header file paths
cryptl :
	$(RM) -f cryptl
	$(LN) -s . cryptl

AESAVS : AESAVS.cpp cryptl
	$(CXX) -c $(CXXFLAGS) $< -o AESAVS.o
	$(CXX) -o $@ AESAVS.o

ED25519_test : ED25519_test.cpp cryptl
	$(CXX) -c $(CXXFLAGS) $< -o ED25519_test.o
	$(CXX) -o $@ ED25519_test.o

SHAVS : SHAVS.cpp cryptl
	$(CXX) -c $(CXXFLAGS) $< -o SHAVS.o
	$(CXX) -o $@ SHAVS.o
