# Makefile for auto_shutdown.c

CC = gcc
CFLAGS = -Wall -O2
TARGET = auto_shutdown

# Windows 下需要链接 ws2_32 库
ifeq ($(OS),Windows_NT)
	LIBS = -lws2_32
else
	LIBS =
endif

SRC = auto_shutdown.c cJSON.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LIBS)

clean:
	$(RM) $(TARGET)