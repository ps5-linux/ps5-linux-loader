#ifndef FW_1340_PORTING_H
#define FW_1340_PORTING_H

#include <stdint.h>

#define FW_1340_VERSION 0x1340u

int is_fw_1340_target(uint16_t fw);
void notify_fw_1340_porting_status(uint16_t fw);

#endif