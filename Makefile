# Add _DEFAULT_SOURCE macro to avoid compiler errors for some GNU expressions
CFLAGS = -std=c99 -g -pedantic -Wall -Wextra -D_DEFAULT_SOURCE

SRCDIR = src
INCDIR = include
OBJDIR = obj
BINDIR = bin
QCBORDIR = 3rdparty/QCBOR

LIBINCLUDE = -I/usr/include \
             -I/usr/local/include \
             -I./$(QCBORDIR)/inc

LDPATH =     -L/usr/local/lib/ \
             -L/usr/lib/x86_64-linux-gnu \
             -L./$(QCBORDIR)

LIBS =        coap-3 crypto
STATIC_LIBS = qcbor

LDFLAGS_DYNAMIC = $(addprefix -l, $(LIBS))

LDFLAGS_STATIC = $(addprefix -l, $(STATIC_LIBS))

SOURCES = $(wildcard $(SRCDIR)/*.c)

INCLUDE = -I$(INCDIR)

OBJECTS = $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SOURCES))

TARGET = $(addprefix $(BINDIR)/, fobnail-platform-owner)

EXTERNALS = $(addprefix $(QCBORDIR)/, libqcbor.a)

.PHONY: all clean

## --- targets ------------------------------------------------------------ ##

all: LDFLAGS = $(LDFLAGS_DYNAMIC) $(LDFLAGS_STATIC)
all: $(EXTERNALS) $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $^ $(CFLAGS) $(INCLUDE) $(LIBINCLUDE) $(LDPATH) $(LDFLAGS) -g -o $@

## --- objects ------------------------------------------------------------ ##

$(QCBORDIR)/libqcbor.a:
	$(MAKE) -C $(@D) $(@F) CMD_LINE="-DUSEFULBUF_DISABLE_ALL_FLOAT"

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(@D)
	$(CC) $< $(INCLUDE) $(LIBINCLUDE) $(LDPATH) $(LDFLAGS) $(CFLAGS) -g -o $@ -c

clean:
	$(MAKE) -C $(QCBORDIR) clean
	$(RM) bin/*
	$(RM) obj/*.*
