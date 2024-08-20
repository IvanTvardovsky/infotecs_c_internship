CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lssl -lcrypto -static

OBJECTS = main.o hash.o integrity.o

all: integrity_tool

integrity_tool: $(OBJECTS)
	$(CC) -o $@ $(OBJECTS) $(LDFLAGS)

clean:
	rm -f $(OBJECTS) integrity_tool

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
