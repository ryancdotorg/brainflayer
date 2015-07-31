HEADERS = bloom.h
OBJECTS = brainflayer.o hash160.o hash256.o bloom.o
BINARIES = brainflayer hex2blf
LIBS = -lssl
CFLAGS = -O2
COMPILE = gcc $(CFLAGS) -g -pedantic -std=gnu99 -Wall -Wextra -funsigned-char -Wno-pointer-sign -Wno-sign-compare

%.o: %.c
	$(COMPILE) -c $< -o $@

hex2blf: hex2blf.o bloom.o
	$(COMPILE) hex2blf.o bloom.o -o hex2blf

balezur: $(OBJECTS)
	$(COMPILE) $(OBJECTS) $(LIBS) -o balezur

all: $(BINARIES)

clean:
	rm -f $(BINARIES) $(OBJECTS)
