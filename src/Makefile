CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -lpthread -lpcap -lconfig

MKDIR_P = mkdir -p
OUT_DIR = ../exe
LIB_DIR = ./lib

# all: directories main
all: directories server client relay

server: backdoor-server.o utils.o pktcap.o isaac_encryption.o
	${CC} ${LDFLAGS} backdoor-server.o utils.o pktcap.o isaac_encryption.o -o ${OUT_DIR}/server

client: backdoor-client.o utils.o pktcap.o isaac_encryption.o
	${CC} ${LDFLAGS} backdoor-client.o utils.o pktcap.o isaac_encryption.o -o ${OUT_DIR}/client

relay: relay.o utils.o pktcap.o isaac_encryption.o
	${CC} ${LDFLAGS} relay.o utils.o pktcap.o isaac_encryption.o -o ${OUT_DIR}/relay

backdoor-server.o: backdoor-server.c backdoor-server.h pktcap.h utils.h 
	${CC} ${CFLAGS} -c backdoor-server.c

backdoor-client.o: backdoor-client.c backdoor-client.h pktcap.h utils.h
	${CC} ${CFLAGS} -c backdoor-client.c

relay.o: relay.c relay.h pktcap.h utils.h
	${CC} ${CFLAGS} -c relay.c

utils.o:  utils.c utils.h
	${CC} ${CFLAGS} -c utils.c

pktcap.o: pktcap.h pktcap.c
	${CC} ${CFLAGS} -c pktcap.c

isaac_encryption.o: lib/isaac_encryption.c lib/isaac_encryption.h
	${CC} ${CFLAGS} -c lib/isaac_encryption.c

clean:
	rm -rf *.o *.c~ *.cpp~ *.h~ Makefile~ ${LIB_DIR}/*.c~ ${LIB_DIR}/*.h~ ${OUT_DIR}/server ${OUT_DIR}/client ${OUT_DIR}/relay

directories: 
	${MKDIR_P} ${OUT_DIR}/
