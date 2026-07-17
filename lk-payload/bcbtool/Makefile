CC = $(CROSS_COMPILE)gcc
CFLAGS = -Wall -Wextra -Ilib
LDFLAGS =

SRCS = bcbtool.c lib/bcblib.c
OBJS = $(SRCS:.c=.o)
TARGET = bcbtool

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
