# ─── simple-ids Makefile ───────────────────────────────────────────────────

CC      = gcc
CFLAGS  = -Wall -Wextra -Wpedantic -std=c11 -O2 -Iinclude
TARGET  = ids
SRCS    = src/main.c src/ids.c
OBJS    = $(SRCS:.c=.o)

# ── default target ──
all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^
	@echo ""
	@echo "  Build successful → ./$(TARGET)"
	@echo "  Run with:  sudo ./$(TARGET) -i eth0 -r rules/rules.conf -v"
	@echo ""

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# ── create log dir before running ──
run: all
	@mkdir -p logs
	sudo ./$(TARGET) -i eth0 -r rules/rules.conf -v

# ── clean build artefacts ──
clean:
	rm -f src/*.o $(TARGET)

# ── check for root (raw sockets need it) ──
check-root:
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "ERROR: must run as root"; exit 1; \
	fi

.PHONY: all run clean check-root
