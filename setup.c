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
#include <libopencm3/stm32/flash.h>
#include <libopencm3/cm3/mpu.h>
#include <libopencm3/cm3/nvic.h>
#include <libopencm3/cm3/scb.h>
#include <libopencm3/stm32/rcc.h>
#include <libopencm3/stm32/gpio.h>
#include <libopencm3/stm32/rng.h>

#include <libopencm3/stm32/fsmc.h>

#include "windows.h"
#include "rng.h"
#include "layout.h"
#include "util.h"
#include "USART_2.h"
#include "memory.h"
#include "lvgl/lvgl.h"
#include "ili9341.h"
#include "touchTft/I2C_FT6236.h"

uint32_t __stack_chk_guard;


// reference RM0090 section 35.12.1 Figure 413
#define USB_OTG_HS_DATA_FIFO_RAM  (USB_OTG_HS_BASE + 0x20000U)
#define USB_OTG_HS_DATA_FIFO_SIZE (4096U)


void LCD_Init(void);
static void lcd_gpio_setup(void);

static inline void __attribute__((noreturn)) fault_handler(const char *line1) {
	//layoutDialog(&bmp_icon_error, NULL, NULL, NULL, line1, "detected.", NULL, "Please unplug", "the device.", NULL);
//        One_Buttons_window("Shutdown!","Some error occured, unplug your OPOLO Wallet", NULL, NULL);
	UART_vPrintfSerial("Fault handler, fault > %s", line1);
	for (;;) {} // loop forever
}

void __attribute__((noreturn)) __stack_chk_fail(void) {
	fault_handler("Stack smashing");
}

void nmi_handler(void)
{
	// Clock Security System triggered NMI
	if ((RCC_CIR & RCC_CIR_CSSF) != 0) {
		fault_handler("Clock instability");
	}
}

void hard_fault_handler(void) {
	fault_handler("Hard fault");
}

void mem_manage_handler(void) {
	fault_handler("Memory fault");
}

void setupLCDAndTouch(void){
    gpio_set(GPIOE, GPIO3 );
    gpio_clear(GPIOE, GPIO4 );

    //initializing LVGL and TFT
	lcd_gpio_setup();

	gpio_set(GPIOE,GPIO3);
	gpio_set(GPIOA,GPIO1);
	gpio_set(GPIOB,GPIO1);

	LCD_Init();

	ili9341_init();
	ILI9341_setRotation(4);

	//msleep(5000);
	lvAndTouchInit();

}

void lvAndTouchInit(void){

	lv_init();
	lv_disp_drv_t disp;
	lv_disp_drv_init(&disp);

	disp.disp_flush = (typeof(disp.disp_flush)) ili9341_flush;
	disp.disp_fill  = (typeof(disp.disp_fill)) ili9341_fill;
	disp.disp_map   = (typeof(disp.disp_map)) ili9341_map;
	lv_disp_drv_register(&disp);


	//Initializing the touch sensor

	touch_init();

	lv_indev_drv_t indev_drv;                       //Descriptor of an input device driver
	lv_indev_drv_init(&indev_drv);                  //Basic initialization
	indev_drv.type = LV_INDEV_TYPE_POINTER;         //The touchpad is pointer type device
	indev_drv.read = FT6236_read;                    //Library ready your touchpad via this function

	lv_indev_drv_register(&indev_drv);              //Finally register the driver

}

void setupApp(void)
{

	//rcc_clock_setup_hse_3v3(&rcc_hse_8mhz_3v3[RCC_CLOCK_3V3_120MHZ]);
	rcc_clock_setup_pll(&rcc_hse_8mhz_3v3[RCC_CLOCK_3V3_168MHZ]);
	// for completeness, disable RNG peripheral interrupts for old bootloaders that had
	// enabled them in RNG control register (the RNG interrupt was never enabled in the NVIC)
	RNG_CR &= ~RNG_CR_IE;
	// the static variables in random32 are separate between the bootloader and firmware.
	// therefore, they need to be initialized here so that we can be sure to avoid dupes.
	// this is to try to comply with STM32F205xx Reference manual - Section 20.3.1:
	// "Each subsequent generated random number has to be compared with the previously generated
	// number. The test fails if any two compared numbers are equal (continuous random number generator test)."
	random32();

	// enable CSS (Clock Security System)
	RCC_CR |= RCC_CR_CSSON;
	gpio_mode_setup(GPIOA, GPIO_MODE_INPUT, GPIO_PUPD_NONE, GPIO4);

	// hotfix for old bootloader
//	gpio_mode_setup(GPIOA, GPIO_MODE_INPUT, GPIO_PUPD_NONE, GPIO9);
//	spi_init_master(SPI1, SPI_CR1_BAUDRATE_FPCLK_DIV_8, SPI_CR1_CPOL_CLK_TO_0_WHEN_IDLE, SPI_CR1_CPHA_CLK_TRANSITION_1, SPI_CR1_DFF_8BIT, SPI_CR1_MSBFIRST);

}

void setupUsb(void){
	// enable OTG HS clock
	rcc_periph_clock_enable(RCC_OTGHS);

	// enable OTG_HS
	gpio_mode_setup(GPIOB, GPIO_MODE_AF, GPIO_PUPD_PULLUP, GPIO12);
	gpio_mode_setup(GPIOB, GPIO_MODE_AF, GPIO_PUPD_NONE, GPIO14 | GPIO15);
	gpio_set_af(GPIOB, GPIO_AF12, GPIO12 | GPIO14 | GPIO15);

	// clear USB OTG_FS peripheral dedicated RAM
	// USB OTG FS = 0x5000 0000 - 0x5003 FFFF, USB OTG HS = 0x4004 0000 - 0x4007 FFFF
	//memset_reg((void *) 0x50000000, (void *) 0x5003FFFF, 0);
	//	memset_reg((void *) 0x40040000, (void *) 0x4007FFFF, 0);
	memset_reg((void *) USB_OTG_HS_DATA_FIFO_RAM, (void *) (USB_OTG_HS_DATA_FIFO_RAM + USB_OTG_HS_DATA_FIFO_SIZE), 0);

}


// Never use in bootloader! Disables access to PPB (including MPU, NVIC, SCB)
void firmware_mpu_setup(void)
{
//#if MEMORY_PROTECT
	// Disable MPU
	MPU_CTRL = 0;

	// Note: later entries overwrite previous ones

	// Bootloader (0x08000000 - 0x0801FFFF, 128 KiB, read-only)
	MPU_RNR = MPU_REGION_NUMBER0;
	MPU_RBAR = FLASH_BASE;
	MPU_RASR = MPU_RASR_ENABLE | MPU_RASR_ATTR_FLASH | MPU_RASR_SIZE_128KB | LL_MPU_REGION_PRIV_RO_URO;
	//MPU_RASR = MPU_RASR_ENABLE | MPU_RASR_ATTR_FLASH | MPU_RASR_SIZE_64KB | LL_MPU_REGION_FULL_ACCESS | MPU_RASR_XN_Msk;

	// Storage#1 (0x08020000 - 0x0803FFFF, 128 KiB, read-write, execute never)
	MPU_RNR = MPU_REGION_NUMBER1;
	MPU_RBAR = FLASH_BASE + 0x20000;
	MPU_RASR = MPU_RASR_ENABLE | MPU_RASR_ATTR_FLASH | MPU_RASR_SIZE_128KB | LL_MPU_REGION_FULL_ACCESS | MPU_RASR_XN_Msk;

	// Firmware (0x08020000 - 0x080BFFFF, 6 * 128 KiB = 1024 KiB except subregion 1 & 2 / 8 at start = 768 KiB, read-only)
	MPU_RNR = MPU_REGION_NUMBER3;
	MPU_RBAR = FLASH_BASE;
	MPU_RASR = MPU_RASR_ENABLE | MPU_RASR_ATTR_FLASH | MPU_RASR_SIZE_1MB | LL_MPU_REGION_PRIV_RO_URO | MPU_SUBREGION_DISABLE(0x01) | MPU_SUBREGION_DISABLE(0x02);

	// Firmware extra (0x08120000 - 0x081FFFFF, 6 * 128 KiB = 1024 KiB except subregion 1 & 2/8 at start = 768 KiB, read-only)
	MPU_RNR = MPU_REGION_NUMBER4;
	MPU_RBAR = FLASH_BASE + 0x100000;
	MPU_RASR = MPU_RASR_ENABLE | MPU_RASR_ATTR_FLASH | MPU_RASR_SIZE_1MB | LL_MPU_REGION_PRIV_RO_URO | MPU_SUBREGION_DISABLE(0x01) | MPU_SUBREGION_DISABLE(0x02);

	// SRAM (0x20000000 - 0x2002FFFF, 192 KiB = 256 KiB except 2/8 at end, read-write, execute never)
	MPU_RNR = MPU_REGION_NUMBER5;
	MPU_RBAR = SRAM_BASE;
	MPU_RASR = MPU_RASR_ENABLE | MPU_RASR_ATTR_SRAM | MPU_RASR_SIZE_256KB | LL_MPU_REGION_FULL_ACCESS | MPU_RASR_XN_Msk | MPU_SUBREGION_DISABLE(0xC0);

	// Peripherals (0x40000000 - 0x5FFFFFFF, read-write, execute never)
	// External RAM (0x60000000 - 0x7FFFFFFF, read-write, execute never)
	MPU_RNR = MPU_REGION_NUMBER6;
	MPU_RBAR = PERIPH_BASE;
	MPU_RASR = MPU_RASR_ENABLE | MPU_RASR_ATTR_PERIPH | MPU_RASR_SIZE_1GB | LL_MPU_REGION_FULL_ACCESS | MPU_RASR_XN_Msk;

	// CCMRAM (0x10000000 - 0x1000FFFF, read-write, execute never)
	MPU_RNR = MPU_REGION_NUMBER7;
	MPU_RBAR = CCMDATARAM_BASE;
	MPU_RASR = MPU_RASR_ENABLE | MPU_RASR_ATTR_SRAM | MPU_RASR_SIZE_64KB | LL_MPU_REGION_FULL_ACCESS | MPU_RASR_XN_Msk;

	//Enable MPU
	MPU_CTRL = MPU_CTRL_ENABLE | MPU_CTRL_HFNMIENA;

	// Enable memory fault handler
	SCB_SHCSR |= SCB_SHCSR_MEMFAULTENA;

	__asm__ volatile("dsb");
	__asm__ volatile("isb");

	// Switch to unprivileged software execution to prevent access to MPU
	set_mode_unprivileged();

//#endif
}

static void lcd_gpio_setup(void)
{
	rcc_periph_clock_enable(RCC_GPIOA);
	rcc_periph_clock_enable(RCC_GPIOB);
	rcc_periph_clock_enable(RCC_GPIOC);
	rcc_periph_clock_enable(RCC_GPIOD);
	rcc_periph_clock_enable(RCC_GPIOE);

    gpio_mode_setup(GPIOC, GPIO_MODE_OUTPUT, GPIO_PUPD_NONE,  GPIO5);

    gpio_mode_setup(GPIOC, GPIO_MODE_OUTPUT, GPIO_PUPD_NONE,  GPIO4);

    gpio_mode_setup(GPIOD, GPIO_MODE_OUTPUT, GPIO_PUPD_NONE,  GPIO7);

	/* Set GPIO0 (in GPIO port A) to 'input open-drain'. */
    gpio_mode_setup(GPIOA, GPIO_MODE_INPUT, GPIO_PUPD_PULLUP, GPIO4);
    gpio_mode_setup(GPIOB, GPIO_MODE_INPUT, GPIO_PUPD_NONE, GPIO0);
}


/*
FSMC_NE1  -> LCD_CS PD7
FSMC_NWE  -> LCD_WR PD5
FSMC_NOE  -> LCD_RD PD4
FSMC_A18  -> LCD_RS PD13  FSMC_A18

LCD_RST -> 3V   (or a GPIO output, set LOW to reset at the start, then back to HIGH)

FSMC_D0   -> LCD_D0 PD14
FSMC_D1   -> LCD_D1 PD15
FSMC_D2   -> LCD_D2 PD0
FSMC_D3   -> LCD_D3 PD1

FSMC_D4   -> LCD_D4 PE7
FSMC_D5   -> LCD_D5 PE8
FSMC_D6   -> LCD_D6 PE9
FSMC_D7   -> LCD_D7 PE10
*/

#define FSMC_BCR_RESERVED (1 << 7)
#define FSMC_BCR_MWID_8BITS             (0x0 << 4)

void LCD_Init(void)
{
    gpio_set(GPIOC, GPIO4);

    uint16_t portd_gpiocontrol = GPIO7 | GPIO5 | GPIO4 | GPIO13;
    uint16_t portd_gpiodata = GPIO0 | GPIO1 | GPIO14 | GPIO15;
    uint16_t porte_gpiodata = GPIO7 | GPIO8 | GPIO9 | GPIO10;

    rcc_peripheral_enable_clock(&RCC_AHB1ENR, RCC_AHB1ENR_IOPDEN); // FSMC PORD
    rcc_peripheral_enable_clock(&RCC_AHB1ENR, RCC_AHB1ENR_IOPEEN); // FSMC PORD
    rcc_peripheral_enable_clock(&RCC_AHB3ENR, RCC_AHB3ENR_FSMCEN);

    gpio_set_af(GPIOD, GPIO_AF12, portd_gpiocontrol | portd_gpiodata);
    gpio_mode_setup(GPIOD, GPIO_MODE_AF, GPIO_PUPD_NONE, portd_gpiocontrol | portd_gpiodata);

    gpio_set_output_options(GPIOD, GPIO_OTYPE_PP, GPIO_OSPEED_100MHZ, portd_gpiocontrol | portd_gpiodata);
    gpio_set_af(GPIOE, GPIO_AF12, porte_gpiodata);
    gpio_mode_setup(GPIOE, GPIO_MODE_AF, GPIO_PUPD_NONE, porte_gpiodata);
    gpio_set_output_options(GPIOE, GPIO_OTYPE_PP, GPIO_OSPEED_100MHZ, porte_gpiodata);

    rcc_periph_clock_enable(RCC_FSMC);

 /* Extended mode, write enable, 8 bit access, bank enabled */
    FSMC_BCR1 = FSMC_BCR_WREN | FSMC_BCR_MWID_8BITS | FSMC_BCR_MBKEN;

    /* Read & write timings */
    FSMC_BTR1  = FSMC_BTR_DATASTx(2) | FSMC_BTR_ADDHLDx(0) | FSMC_BTR_ADDSETx(1) | FSMC_BTR_ACCMODx(FSMC_BTx_ACCMOD_B);
    FSMC_BWTR1 = FSMC_BTR_DATASTx(2) | FSMC_BTR_ADDHLDx(0) | FSMC_BTR_ADDSETx(1) | FSMC_BTR_ACCMODx(FSMC_BTx_ACCMOD_B);

    // RESET LCD
    gpio_set(GPIOC, GPIO4);
    delay(20);

    gpio_clear(GPIOC, GPIO4);
    delay(1);

    gpio_set(GPIOC, GPIO4);
    delay(10);
}


