CFLAGS=-Wall

all: dm io-latency-test

io-latency-test: io-latency-test.c
	$(CC) -pthread -lm -o $@ $^

install:

clean:
	rm -f dm io-latency-test

distclean: clean
