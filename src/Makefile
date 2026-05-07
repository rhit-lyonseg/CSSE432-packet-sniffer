all: sniffer

sniffer: sniffer.o
	gcc sniffer.o -o sniffer -g -lm -Wall

client.o: sniffer.c
	gcc sniffer.c -c -g -lm -Wall

clean:
	rm -f *.o sniffer