# Compiler
CC = gcc

# Source and target
SRC = main.c
OUT = kernel-rop-finder
STATIC-OUT = kernel-rop-finder-static

# Common compiler flags
CFLAGS = -Wall

# Shared dynamic linker flags
LDLIBS = -lcapstone -lelf

# Static linker flags
STATIC_LDLIBS = -static -lcapstone -lelf -lz -lzstd

# Default target: dynamic build
all: $(OUT)

# Dynamic build
$(OUT): $(SRC)
	$(CC) $(CFLAGS) -o $(OUT) $(SRC) $(LDLIBS)

# Static build
static:
	$(CC) $(CFLAGS) -o $(STATIC-OUT) $(SRC) $(STATIC_LDLIBS)

# Clean target
clean:
	rm -f $(OUT)