# X86
CC=gcc

# ARM
#CC=aarch64-none-linux-gnu-gcc

SRC := .

TARGET := tcpparse

source += tcpparse.c crc.c
	
objs := $(patsubst %.c, %.o, $(source))  

all: $(TARGET)

$(TARGET):$(objs) 
	$(CC) -o $@  $(LDFLAGS) $(objs) -ldl -lrt -lpthread -lm -static

$(objs) : %.o : %.c
	$(CC) -o $@ -c $< $(INCLUDE_DIR)

.PHONY : clean 
clean:
	rm -rf *.o
	rm -rf $(TARGET)
