# Piotr Dobiech 316625

CC = gcc
CFLAGS = -std=gnu17 -Wall -Wextra

BINARY_NAME := traceroute
SRCS := ip_address.c icmp.c main.c
OBJS := $(SRCS:%.c=%.o)

$(BINARY_NAME): $(OBJS)
	$(CC) $(OBJS) -o $@

%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	rm $(OBJS)

cleandist:
	rm $(OBJS) $(BINARY_NAME)
