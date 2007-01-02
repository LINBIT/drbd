PROGRAMS=show_size  access_and_verify #drbd_states
CFLAGS=-Wall -I../drbd

all: $(PROGRAMS)

clean: 
	rm -f $(PROGRAMS)

distclean: clean

drbd_states: drbd_states.o ../drbd/linux/drbd.h ../drbd/drbd_strings.o
	gcc -o drbd_states drbd_states.o ../drbd/drbd_strings.o
