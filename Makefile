HEADERS = bloom.h
OBJECTS = brainflayer.o bloom.o hex2blf.o
BINARIES = brainflayer hex2blf
LIBS = -lssl -lrt -lcrypto -lz -ldl -lsecp256k1 -lgmp
CFLAGS = -O2
COMPILE = gcc $(CFLAGS) -g -pedantic -std=gnu99 -Wall -Wextra -funsigned-char -Wno-pointer-sign -Wno-sign-compare

%.o: %.c
	$(COMPILE) -c $< -o $@

hex2blf: hex2blf.o bloom.o
	$(COMPILE) -static $^ $(LIBS) -o hex2blf

brainflayer: brainflayer.o bloom.o
	$(COMPILE) -static $^ $(LIBS) -o brainflayer

all: $(BINARIES)

clean:
	rm -f $(BINARIES) $(OBJECTS)
