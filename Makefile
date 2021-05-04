LDFLAGS = -lpcap -lpthread
CFLAGS = -O3 -Wall 

.PHONY: all
all: ipdr 
	strip ipdr 

ipdr: ipdr.c util.c
	gcc ipdr.c  -o ipdr $(CFLAGS) $(LDFLAGS) 

clean:
	rm -f ipdr 
