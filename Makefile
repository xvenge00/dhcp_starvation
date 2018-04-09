CFLAGS = -std=gnu99 -pedantic
CC = gcc
PROJ = ipk-dhcpstarve
FILES = $(PROJ).c $(PROJ).h Makefile README.md dokumentace.pdf

all:
	make ipk-dhcpstarve

clean:
	rm *.o ipk-dhcpstarve

ipk-dhcpstarve: ipk-dhcpstarve.o
	$(CC) $(CFLAGS) $(PROJ).c $(PROJ).h -o $(PROJ)

pack:
	zip xvenge00.zip $(FILES)
