PYTHON ?= python3
CC ?= cc
PKG_CONFIG ?= pkg-config
CPPFLAGS ?=
CFLAGS ?= -O2
LDFLAGS ?=
OPENSSL_CFLAGS = $(shell $(PKG_CONFIG) --cflags libcrypto)
OPENSSL_LIBS = $(shell $(PKG_CONFIG) --libs libcrypto)
NATIVE_CFLAGS = -std=c11 -Wall -Wextra -Werror -Wformat=2 -Wformat-security -D_FILE_OFFSET_BITS=64 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE
NATIVE_LDFLAGS = -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack

.PHONY: native check clean

native: bin/mvt-hash

bin/mvt-hash: native/mvt-hash.c native/mvt-tools.c Makefile
	$(CC) $(CPPFLAGS) $(OPENSSL_CFLAGS) $(CFLAGS) $(NATIVE_CFLAGS) $< -o $@ $(LDFLAGS) $(NATIVE_LDFLAGS) $(OPENSSL_LIBS)

check: native
	$(PYTHON) -B tools/check.py

clean:
	$(RM) bin/mvt-hash
