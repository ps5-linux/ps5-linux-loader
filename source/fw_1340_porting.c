#include "fw_1340_porting.h"
#include "utils.h"

int is_fw_1340_target(uint16_t fw) { return fw == FW_1340_VERSION; }

void notify_fw_1340_porting_status(uint16_t fw) {
  if (!is_fw_1340_target(fw))
    return;

  notify("Firmware 13.40 (26.04-13.40.00) is a porting target on this fork.\n"
         "Public kernel exploit, HV defeat offsets, and resume shellcode\n"
         "offsets are not available yet — booting Linux is not possible.\n"
         "Track branch fw-13.40-research for future updates.\n");
}