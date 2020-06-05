/*
 * This file is part of the TREZOR project, https://trezor.io/
 *
 * Copyright (C) 2014 Pavol Rusnak <stick@satoshilabs.com>
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __UTIL_H_
#define __UTIL_H_

#include <stdint.h>
#include <stdbool.h>
#include <setup.h>

#if !EMULATOR
#include "scb.h"
#include "vector.h"
#endif

// Statement expressions make these macros side-effect safe
#define MIN(a, b) ({ typeof(a) _a = (a); typeof(b) _b = (b); _a < _b ? _a : _b; })
#define MAX(a, b) ({ typeof(a) _a = (a); typeof(b) _b = (b); _a > _b ? _a : _b; })

void delay(uint32_t wait);
void printHex(const uint8_t* data, uint32_t len, char * str);

// converts uint32 to hexa (8 digits)
void uint32hex(uint32_t num, char *str);

// converts data to hexa
void data2hex(const void *data, uint32_t len, char *str);

// read protobuf integer and advance pointer
uint32_t readprotobufint(const uint8_t **ptr);

void randBytes(uint8_t* randomData, uint32_t size);

uint8_t writeLengthWithArray(uint8_t  * byteArray, uint8_t * value, uint8_t valueSize);

uint8_t arrayWrite2Bytes(uint8_t * byteArray, uint16_t val);

uint8_t arrayWrite4Bytes(uint8_t * byteArray, int val);

extern void __attribute__((noreturn)) shutdown(void);

#if !EMULATOR
// defined in memory.ld
extern uint8_t _ram_start[], _ram_end[];
extern uint8_t _mem_stack[];

// defined in startup.s
extern void memset_reg(void *start, void *stop, uint32_t val);

#define FW_SIGNED       0x5A3CA5C3
#define FW_UNTRUSTED    0x00000000

static inline void __attribute__((noreturn)) jump_to_firmware(const vector_table_t *vector_table2, int trust)
{
	if (FW_SIGNED == trust) {                 // trusted signed firmware
		SCB_VTOR = (uint32_t)vector_table2;    // * relocate vector table
		// Set stack pointer
		__asm__ volatile("msr msp, %0" :: "r" (vector_table2->initial_sp_value));
	} else {                                  // untrusted firmware
		firmware_mpu_setup();                 // * configure MPU
		__asm__ volatile("msr msp, %0" :: "r" (_mem_stack));
	}

	// Jump to address
	vector_table2->reset();

	// Prevent compiler from generating stack protector code (which causes CPU fault because the stack is moved)
	for (;;);
}

static inline void set_mode_unprivileged(void)
{
	// http://infocenter.arm.com/help/topic/com.arm.doc.dui0552a/CHDBIBGJ.html
	__asm__ volatile("msr control, %0" :: "r" (0x1));
}

static inline bool is_mode_unprivileged(void)
{
	uint32_t r0;
	__asm__ volatile("mrs %0, control" : "=r" (r0));
	return r0 & 1;
}

#else /* EMULATOR */

static inline bool is_mode_unprivileged(void)
{
	return true;
}
#endif

#endif
