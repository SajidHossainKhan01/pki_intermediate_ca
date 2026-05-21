# Makefile — CSE PKI C/OpenSSL Example
# University of Dhaka

CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -std=c11
LDFLAGS = -lssl -lcrypto

TARGET  = verify_tls
SRC     = verify_tls.c

.PHONY: all clean run

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

# Install OpenSSL dev headers if missing:
#   Ubuntu/Debian: sudo apt install libssl-dev
#   RHEL/CentOS:   sudo yum install openssl-devel
#   macOS:         brew install openssl
#                  export PKG_CONFIG_PATH=$(brew --prefix openssl)/lib/pkgconfig
