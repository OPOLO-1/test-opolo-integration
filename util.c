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

#include "util.h"
#include "USART_2.h"
#include "timer.h"
#include "rng.h"
#include <string.h>
inline void delay(uint32_t wait)
{
	delayMS(wait);

	//while (--wait > 0) __asm__("nop");
}

static const char *hexdigits = "0123456789ABCDEF";

void uint32hex(uint32_t num, char *str)
{
	for (uint32_t i = 0; i < 8; i++) {
		str[i] = hexdigits[(num >> (28 - i * 4)) & 0xF];
	}
}

// converts data to hexa
void data2hex(const void *data, uint32_t len, char *str)
{
	const uint8_t *cdata = (uint8_t *)data;
	for (uint32_t i = 0; i < len; i++) {
		str[i * 3    ] = hexdigits[(cdata[i] >> 4) & 0xF];
		str[i * 3 + 1] = hexdigits[cdata[i] & 0xF];
		str[i * 3 + 2 ] = ' ';
	}
	str[len * 3] = 0;
}

char  outputStr[1024*2];

void printHex(const uint8_t *temp, uint32_t count, char * str){

	USART_Debug(" \n ");
	USART_Debug(str);
	data2hex(temp, count , outputStr);
	USART_Debug(outputStr);
	USART_Debug(" \n ");
}

uint32_t readprotobufint(const uint8_t **ptr)
{
	uint32_t result = (**ptr & 0x7F);
	if (**ptr & 0x80) {
		(*ptr)++;
		result += (**ptr & 0x7F) * 128;
		if (**ptr & 0x80) {
			(*ptr)++;
			result += (**ptr & 0x7F) * 128 * 128;
			if (**ptr & 0x80) {
				(*ptr)++;
				result += (**ptr & 0x7F) * 128 * 128 * 128;
				if (**ptr & 0x80) {
					(*ptr)++;
					result += (**ptr & 0x7F) * 128 * 128 * 128 * 128;
				}
			}
		}
	}
	(*ptr)++;
	return result;
}

void randBytes(uint8_t* randomData, uint32_t size){
	for(uint8_t count=0; count<size; count++){
		randomData[count] = (uint8_t)random32();
	}
}

uint8_t writeLengthWithArray(uint8_t  * byteArray, uint8_t * value, uint8_t valueSize){
	uint8_t index = 0;
	byteArray[index++] = valueSize;
	memcpy(&byteArray[index], value, valueSize);
	index += valueSize;
	return index;
}

uint8_t arrayWrite2Bytes(uint8_t * byteArray, uint16_t val){
	uint8_t index = 0;
	byteArray[index++] = val%256;
	byteArray[index++] = val/256;
	return index;
}

uint8_t arrayWrite4Bytes(uint8_t * byteArray, int val){
	uint8_t index = 0;

	int filter = 0xFF000000;
	uint8_t shift = 24;
	while(index<4)
	{
		byteArray[index++] = (filter & val) >> shift;
		filter = filter >> 8;
		shift = shift - 8;
	}
	return index;
}

