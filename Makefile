CFLAGS = -O2 -Wall -Wextra
LIBS = -lgcrypt

all: test

clean:
	rm -f test *.o *~

rebuild: clean all

test: fsprg.o test.o
	$(CC) $(CFLAGS) $(LIBS) -o test fsprg.o test.o

test.o: test.c fsprg.h
	$(CC) $(CFLAGS) -c test.c

fsprg.o: fsprg.c fsprg.h
	$(CC) $(CFLAGS) -c fsprg.c
