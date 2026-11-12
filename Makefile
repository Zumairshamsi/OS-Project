CC      := gcc
CFLAGS  := -std=c11 -D_GNU_SOURCE -Wall -Wextra -Wpedantic -g -O0 -Iinclude
LDFLAGS :=
TARGET  := mini_strace
SRCS    := $(wildcard src/*.c)
OBJS    := $(SRCS:src/%.c=build/%.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

build/%.o: src/%.c include/tracer.h | build
	$(CC) $(CFLAGS) -c $< -o $@

build:
	mkdir -p build

asan: CFLAGS  += -fsanitize=address,undefined -fno-omit-frame-pointer
asan: LDFLAGS += -fsanitize=address,undefined
asan: clean $(TARGET)

clean:
	rm -rf build $(TARGET)

.PHONY: all asan clean