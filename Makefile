CC=gcc
CFLAGS=-g -O2 -I/usr/local/include/glib-2.0 -I/usr/local/lib/glib-2.0/include -I/usr/include/libpurple   -I/usr/local/include/glib-2.0 -I/usr/local/lib/glib-2.0/include   -Wfatal-errors 
LDFLAGS=  -lpurple 
purpled: purpled.o
purpled.o: purpled.c
clean:
	rm -f *.o
