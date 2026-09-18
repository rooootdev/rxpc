CC ?= cc

CFLAGS ?= -O2 -Wall -Wextra -Wno-unused-parameter
CFLAGS += -std=c11

UNAME_S := $(shell uname -s)

OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS   := $(shell pkg-config --libs openssl 2>/dev/null)

ifeq ($(UNAME_S),Darwin)
POC_CFLAGS := $(OPENSSL_CFLAGS)
POC_LIBS := $(OPENSSL_LIBS) -pthread
else
POC_CFLAGS :=
POC_LIBS :=
endif

BUILD := build
LIB := $(BUILD)/librxpc.a
POC := $(BUILD)/poc

LIB_OBJS := \
	$(BUILD)/rxpc.o \
	$(BUILD)/tunnel.o

.PHONY: all poc clean
all: $(LIB)
poc: $(POC)

$(LIB): $(LIB_OBJS)
	mkdir -p $(BUILD)
	ar rcs $@ $^

$(BUILD)/tunnel.o: src/tunnel.c include/tunnel.h
	mkdir -p $(BUILD)
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) -Iinclude -c -o $@ src/tunnel.c

$(BUILD)/rxpc.o: src/rxpc.c include/rxpc.h
	mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -Iinclude -c -o $@ src/rxpc.c

$(POC): src/poc.c $(LIB)
	mkdir -p $(BUILD)
	$(CC) $(CFLAGS) $(POC_CFLAGS) \
		-Iinclude \
		-o $@ src/poc.c $(LIB) $(POC_LIBS)

clean:
	rm -rf $(BUILD)
