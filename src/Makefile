CC	= gcc
CFLAGS	= -Wall
LDFLAGS	= -lsodium -lcrypto -lb64 /usr/local/lib64/libcbor.a

CLIENT_OBJFILES	= 	EdhocMessage1.o cryptoFunctions.o edhocClient.o
CLIENT_TARGET	=	edhoc-client

$(CLIENT_TARGET) : $(CLIENT_OBJFILES)
	$(CC) $(CFLAGS) -o $(CLIENT_TARGET) $(CLIENT_OBJFILES) $(LDFLAGS)
	
clean:
	rm $(CLIENT_OBJFILES) $(CLIENT_TARGET)