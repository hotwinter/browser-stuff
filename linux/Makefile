IDIR =
CC=aarch64-linux-android-gcc
CFLAGS=-static -Wall

ODIR=.
LDIR =

LIBS=

_DEPS = 
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

_OBJ = util.o getroot.o exp.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

poc_orig: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

$(ODIR)/%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

.PHONY: clean

clean:
	rm -f $(ODIR)/*.o *~ core $(INCDIR)/*~ 
	rm ./poc_orig
