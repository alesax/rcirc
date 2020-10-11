TARGET = rcirc

all: $(TARGET)

.SUFFIXES: .c .h .o .html

OBJS = rcirc.o util.o json.o

CPPFLAGS = -I. -pedantic -Wall
LDFLAGS = -lpthread -lwebsockets -ljson-c

clean:
	rm -f $(OBJS) $(TARGET)

install:
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	cp -f $(TARGET) $(DESTDIR)$(PREFIX)/bin


$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
