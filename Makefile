# Makefile

# Compiler
CC = gcc

# Source and target
SRC = main.c
OUT = kernel-rop-finder

# Compiler flags
CFLAGS = -Wall

LDFLAGS = -lcapstone -lelf

# Default target
all: $(OUT)

# Linking target
$(OUT): $(SRC)
	$(CC) $(CFLAGS) -o $(OUT) $(SRC) $(LDFLAGS)

# Clean target
clean:
	rm -f $(OUT)
