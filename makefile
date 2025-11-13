CC = gcc
CFLAGS = `pkg-config --cflags fuse3` -Wall -Wextra -O2
LIBS = `pkg-config --libs fuse3`
TARGET = backupfs

all: $(TARGET)

$(TARGET): backupfs.c
	$(CC) $(CFLAGS) -o $(TARGET) backupfs.c $(LIBS)

clean:
	rm -f $(TARGET)
