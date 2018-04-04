CC=gcc
CFLAGS=-Ofast -m64 -Wall -Wno-unused-function -Wno-pointer-sign -funsafe-loop-optimizations \
    -I. -Isecp256k1 -Isecp256k1/include -IOpenCL
LDFLAGS=$(CFLAGS)
LDLIBS=-I. -Isecp256k1 -Isecp256k1/include -lm -lcrypto -lssl -lpthread -lOpenCL 

OBJS=vanitygen.o base58.o

all: vanitygen

install: all
	cp --remove-destination -p vanitygen /usr/local/bin/

clean:
	rm -f vanitygen *.o sha256/*.o

distclean: clean
	$(MAKE) -C secp256k1 distclean


vanitygen: $(OBJS)

$(OBJS): Makefile *.h secp256k1/src/libsecp256k1-config.h secp256k1/src/ecmult_static_context.h

secp256k1/src/libsecp256k1-config.h:
	(cd secp256k1;./autogen.sh;./configure)

secp256k1/src/ecmult_static_context.h:
	$(MAKE) -C secp256k1 src/ecmult_static_context.h
