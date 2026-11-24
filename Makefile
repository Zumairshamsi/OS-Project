CC      := gcc
CFLAGS  := -std=c11 -D_GNU_SOURCE -Wall -Wextra -Wpedantic -g -O0 -Iinclude -Ibuild
LDFLAGS :=
TARGET  := mini_strace
SRCS    := $(wildcard src/*.c)
OBJS    := $(SRCS:src/%.c=build/%.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

build/%.o: src/%.c include/tracer.h | build
	$(CC) $(CFLAGS) -c $< -o $@

# syscalls.c includes the generated tables
build/syscalls.o: build/tables.inc

build/tables.inc: tools/gen_tables.sh | build
	CC="$(CC)" sh tools/gen_tables.sh $@

build:
	mkdir -p build

# Debug build with AddressSanitizer (as listed in the proposal)
asan: CFLAGS  += -fsanitize=address,undefined -fno-omit-frame-pointer
asan: LDFLAGS += -fsanitize=address,undefined
asan: clean $(TARGET)

clean:
	rm -rf build $(TARGET)

.DELETE_ON_ERROR:
test: all
	bash tests/run_tests.sh

bench: all
	bash tests/bench.sh

samples: all
	bash tests/samples.sh

.PHONY: all asan clean test bench samples