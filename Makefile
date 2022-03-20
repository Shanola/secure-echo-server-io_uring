
CC=gcc
CCFLAGS ?= -Wall -O2 -D_GNU_SOURCE -luring -lwolfssl
OBJS = \
    src/secure.o \
    src/mainloop.o
DEPS = src/secure.h
TARGET = echoserver
.PHONY: clean all

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $<

all: $(TARGET)

client:
	$(CC) client.c -o $@ $^ $(CCFLAGS)

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(CCFLAGS)

clean:
	rm -f $(TARGET) client src/secure.o src/mainloop.o 
