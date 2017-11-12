vpath %.h include
vpath %.c src
vpath %.o obj
vpath main bin

OPATH = obj
CPATH = src
BPATH = bin
CC = gcc
CFLAGS = -g -Wall -Wextra
IFLAGS = -Iinclude
LDLIBS =  -lpcap

ALL = all
EXEC = analyse
OBJFILES = obj/main.o obj/my_ethernet.o obj/my_ip.o obj/packet_processing.o


$(ALL) : $(EXEC)

$(EXEC) : $(OBJFILES)
	$(CC) -o $@ $^ $(LDLIBS)
#	mv $@ $(BPATH)
	
$(OPATH)/%.o : $(CPATH)/%.c
	$(CC) $(CFLAGS) -c $< $(IFLAGS) -o $@

clean : 
	rm -r $(OPATH)/* #$(BPATH)/* 
