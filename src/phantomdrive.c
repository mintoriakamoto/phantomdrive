#include "phantomdrive.h"
#include "phantomdrive_crypto.h"
#include "unlock_file.h"
#include "bot_state.h"
#include "CH56x_ecdc.h"
#include "debug.h"
#include "CH56x_usb20_devbulk.h"
#include <stdbool.h>
#include <string.h>

static volatile uint8_t phantomdrive_state = STATE_LOCKED;

static uint8_t salt_bytes[KDF_SALT_SIZE] = {0};

void phantomdrive_init(uint64_t unique_id)
{
	for (size_t i = 0; i < KDF_SALT_SIZE; i++) {
		salt_bytes[i] = (uint8_t)(unique_id >> (8 * i));
	}

	log_printf("Salt:");
	for (size_t i = 0; i < KDF_SALT_SIZE; i++) {
		cprintf("%02x", salt_bytes[i]);
	}
	cprintf("\r\n");


	R16_ECEC_CTRL = 0;
	R8_ECDC_INT_FG = 0xFF;

	g_bot.capacity = LOCKED_SECTORS;
	phantomdrive_state = STATE_LOCKED;
	log_printf("phantomdrive: locked, %lu sectors\r\n", LOCKED_SECTORS);
}

bool phantomdrive_is_locked(void) {
	return phantomdrive_state == STATE_LOCKED;
}

void phantomdrive_unlock(const uint8_t *password, size_t password_len)
{
	USB20_Device_Init(DISABLE);
	if (!unlock_file_delete()) {
		PFIC_EnableIRQ(USBHS_IRQn);
		USB20_Device_Init(ENABLE);
		return;
	}

	// We make a custom salt per-device
	phantomdrive_crypto_unlock(password, password_len, salt_bytes);

	g_bot.capacity = TF_EMMCParam.EMMCSecNum - LOCKED_SECTORS;
	phantomdrive_state = STATE_UNLOCKED;

	log_printf("phantomdrive: unlocked, %lu sectors\r\n", g_bot.capacity);

	g_bot.transfer_flags = 0;
	g_bot.read_pending = false;
	g_bot.write_pending = false;
	PFIC_EnableIRQ(USBHS_IRQn);
	USB20_Device_Init(ENABLE);

	log_printf("phantomdrive: re-enumerated\r\n");
}

void phantomdrive_ecdc_disable_data_path(void)
{
	R16_ECEC_CTRL &= ~(RB_ECDC_WRSRAM_EN | RB_ECDC_WRPERI_EN |
	                    RB_ECDC_RDPERI_EN | RB_ECDC_MODE_SEL);
}
