CC = $(CROSS_COMPILE)gcc
CFLAGS = -Wall -Wextra -Ilib
LDFLAGS =

SRCS = idmetool.c lib/idmelib.c
OBJS = $(SRCS:.c=.o)
TARGET = idmetool

PREFIX ?= /usr/local

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

install: $(TARGET)
	install -Dm755 $(TARGET) $(PREFIX)/bin/$(TARGET)

uninstall:
	rm -f $(PREFIX)/bin/$(TARGET)

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean install uninstall
