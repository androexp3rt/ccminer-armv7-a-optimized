#ifndef AESB_H
#define AESB_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void aesb_single_round(const uint8_t *in, uint8_t *out, uint8_t *expandedKey);

#ifdef __cplusplus
}
#endif

#endif // AESB_H
