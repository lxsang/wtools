## Compiler to use (modify this for cross compile).
CC = gcc
## Other tools you need to modify for cross compile (static lib only).
AR = ar
RANLIB = ranlib
LIBS= -lm

OBJ := iwlib.o

# Other flags
CFLAGS=-Os -W -Wall -Wstrict-prototypes -Wmissing-prototypes -Wshadow \
	-Wpointer-arith -Wcast-qual -Winline -I.
#CFLAGS=-O2 -W -Wall -Wstrict-prototypes -I.

# Standard compilation targets
all:: $(OBJ)
	$(CC) $(CFLAGS) -o wlist $(OBJ) iwlist.c $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<


clean:
	rm -f *.o wlist