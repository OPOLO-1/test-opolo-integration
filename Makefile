TOP_DIR       := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
CC  =   gcc
LIBS    =   -lcheck
CFLAGS  =   -I.
CFLAGS  +=  -DUSE_GRAPHENE=1
CFLAGS  +=  -DUSE_RFC6979=1
CFLAGS  +=  -DUSE_CARDANO=1
CFLAGS  +=  -DUSE_BN_PRINT=1
CFLAGS  +=  -DPRODUCTION=1
CFLAGE  +=  -DUSE_KECCAK=1
CFLAGS  +=  -DUSE_MONERO=1
CFLAGS	+=  -I$(TOP_DIR)vendor/opolo-crypto


OBJS += address.o
OBJS += bignum.o
OBJS += ecdsa.o
OBJS += curves.o
OBJS += rfc6979.o
OBJS += secp256k1.o
OBJS += nist256p1.o
OBJS += hmac_drbg.o
OBJS += rand.o
OBJS += memzero.o

OBJS += ed25519-donna/curve25519-donna-32bit.o
OBJS += ed25519-donna/curve25519-donna-helpers.o
OBJS += ed25519-donna/modm-donna-32bit.o
OBJS += ed25519-donna/ed25519-donna-basepoint-table.o
OBJS += ed25519-donna/ed25519-donna-32bit-tables.o
OBJS += ed25519-donna/ed25519-donna-impl-base.o
OBJS += ed25519-donna/ed25519.o
OBJS += ed25519-donna/curve25519-donna-scalarmult-base.o
OBJS += ed25519-donna/ed25519-sha3.o
OBJS += ed25519-donna/ed25519-keccak.o

OBJS += hmac.o
OBJS += bip32.o
OBJS += bip39.o
OBJS += pbkdf2.o
OBJS += base32.o
OBJS += base58.o
OBJS += segwit_addr.o
OBJS += cash_addr.o

#OBJS += crc.o

#OBJS += modtrezorcrypto-bip32.o
OBJS += ripemd160.o
OBJS += sha2.o
OBJS += sha3.o
OBJS += blake256.o
OBJS += blake2b.o
OBJS += groestl.o
OBJS += hasher.o
OBJS += coins.o
OBJS += coin_info.o
OBJS += aes/aescrypt.o
OBJS += aes/aeskey.o
OBJS += aes/aestab.o
OBJS += aes/aes_modes.o
OBJS += cardano.o
# OBJS += monero.o
OBJS += nem.o
# OBJS += tron.o
# OBJS += cosmos.o
# OBJS += fsm_iota.o
OBJS += neo.o

#OBJS += messages-bitcoin.pb.o
SRCS    =   $(OBJS:.o=.c)

all: main.c
	 $(CC) $(CFLAGS) main.c $(SRCS) -o main

clean:

	rm -f *.o
	rm -f *.d
