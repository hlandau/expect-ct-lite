CFLAGS=-O3 -g -Wall

.PHONY: all

all: client

client: client.o
	$(CC) $(CFLAGS) -o "$@" $^ -lcrypto -lssl

client.o: client.c
	$(CC) -c $(CFLAGS) -o "$@" "$<"

