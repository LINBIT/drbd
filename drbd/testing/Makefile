all: receiver sender writetest

writetest: writetest.c
	gcc -g -o writetest writetest.c

receiver: receiver.c
	gcc -g -o receiver receiver.c

sender: sender.c
	gcc -g -o sender sender.c

clean: 
	rm -f receiver sender writetest