CC = gcc
#WCC = x86_64-w64-mingw32-gcc
LD = $(CC)
RM = rm

CFLAGS = -g -Wall -O2 -std=c99 -static
#CFLAGS = -g -Wall -O2 -std=c99
LIBS = -lcrypto 
#WLIBS = -lcrypto -liconv

UNAME_O := $(shell uname -o)
ifeq ($(UNAME_O),Cygwin)
    LIBS += -liconv
endif

OBJECTS = x509lint.o checks.o messages.o asn1_time.o

x509lint: $(OBJECTS)
	$(LD) $(LDFLAGS) -o $@ $(OBJECTS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) $< -c -o $@

clean:
	$(RM) -f x509lint x509lint.exe *.o

checks.o: checks.c checks.h
x509lint.o: x509lint.c checks.h messages.h
messages.o: messages.c checks.h
