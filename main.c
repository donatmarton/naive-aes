#include <avr/io.h>
#include <inttypes.h>
#include "student.h"

uint8_t key[16] =
	{ 0xF3, 0x54, 0x1F, 0xA3, 0x4B, 0x33, 0x9C, 0x0D,
          0x80, 0x23, 0x7A, 0xF9, 0x7C, 0x21, 0xD7, 0x3B };
uint8_t buf[16] =
	{ 0x83, 0x85, 0x1F, 0xAB, 0x60, 0x41, 0xCD, 0xF5,
	  0x4A, 0x41, 0x6C, 0xDA, 0xF0, 0x12, 0xC2, 0xD4 };

int main()
{
    #define n_enc 30                    // number of encryptions
    volatile uint8_t counter = n_enc;	// counter (must be volatile)
    uint8_t *param;

    param = aes128_init(key);

    while (counter > 0) {

	aes128_encrypt(buf, param);	// actual AES encryption

	counter--;

    }

    counter--;

    // Endless loop
    while (1) {
    }

}

void asmInj()
{
  asm volatile("in r28, 0x3d"::);
}
