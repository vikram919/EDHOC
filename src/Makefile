CC	= gcc
CFLAGS	= -Wall
LDFLAGS	= -lcrypto -lb64 -lcbor

CLIENT_OBJFILES	= 	cryptoFunctions.o edhocClient.o
CLIENT_TARGET	=	edhoc-client

$(CLIENT_TARGET) : $(CLIENT_OBJFILES)
	$(CC) $(CFLAGS) -o $(CLIENT_TARGET) $(CLIENT_OBJFILES) $(LDFLAGS)
	
clean:
	rm $(CLIENT_OBJFILES) $(CLIENT_TARGET)