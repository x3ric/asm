CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -lelf -lreadline -ldl -ldw -ljson-c
TARGET = repl
SOURCES = ./src/main.c
ARGS = $(wordlist 2, $(words $(MAKECMDGOALS)), $(MAKECMDGOALS))

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) $(SOURCES) -o $(TARGET) $(LDFLAGS)

run: clean all
	./$(TARGET) $(ARGS)

clean:
	rm -f $(TARGET) *.out

EXTRAS := $(filter-out run clean all, $(MAKECMDGOALS))
.PHONY: $(EXTRAS)
$(EXTRAS):
	@:
.PHONY: all run clean
