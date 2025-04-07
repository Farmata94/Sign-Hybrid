CC = gcc
CFLAGS = -Wall -Wextra -O2
INCLUDES = -ISignature -ISignature/dilithium/ref -ISignature/liboqs/build/include
LDFLAGS = -L Signature/liboqs/build/lib -loqs -lcrypto -lssl

SRC = \
    Signature/hybrid_signature.c \
    Signature/dsa_signature.c \
    Signature/rsa_sign.c \
    Signature/ecdsa_sign.c \
    Signature/dilithium_signature.c \
    Signature/falcon_signature.c \
    Signature/timing.c \
    $(wildcard Signature/dilithium/ref/*.c)

OBJ = $(SRC:.c=.o)
TARGET = hybrid_signature

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)

.PHONY: all clean
