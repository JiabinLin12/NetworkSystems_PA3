CC = gcc
CFLAGS =	-g	-Wall	-Werror	-pthread	-lcrypto
#CFLAGS =	-g	-Wall	-pthread	-lcrypto

all: touch webproxy

webproxy: webproxy.c
	$(CC) webproxy.c $(CFLAGS) -o webproxy
	clear
	./webproxy 8888 20
	
touch:
	touch webproxy.c
clean:
	rm webproxy
