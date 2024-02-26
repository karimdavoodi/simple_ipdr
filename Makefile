LDFLAGS = -lpcap -lpthread
CFLAGS = -O3 -Wall 

.PHONY: all
all: ipdr cgnatd_log
	strip ipdr cgnatd_log

ipdr: ipdr.c util.c
	gcc ipdr.c  -o ipdr $(CFLAGS) $(LDFLAGS) 

cgnatd_log: cgnatd_log.c util.c 
	gcc  cgnatd_log.c -o cgnatd_log $(CFLAGS) $(LDFLAGS)

clean:
	rm -f ipdr cgnatd_log
