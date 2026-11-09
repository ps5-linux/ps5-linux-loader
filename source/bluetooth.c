#include "bluetooth.h"
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define BT_SLOT_COUNT 32
#define BT_SLOT_SIZE 1000
#define BT_INFO_KEY 0x12010100L

extern int sceRegMgrGetBin(long key, void *value, int size);

static void write_name(FILE *out, const uint8_t *name, size_t size) {
  fputc('"', out);
  for (size_t i = 0; i < size; i++) {
    if (name[i] == '"' || name[i] == '\\')
      fputc('\\', out);
    fputc(name[i], out);
  }
  fputc('"', out);
}

int dump_bluetooth_pairings(const char *boot_file_path) {
  const char *slash = strrchr(boot_file_path, '/');
  char output_path[512], temporary_path[512];
  uint8_t slots[BT_SLOT_COUNT][BT_SLOT_SIZE] = {0};
  unsigned count = 0, skipped = 0;
  int ret;

  if (!slash)
    return -1;

  ret = snprintf(output_path, sizeof(output_path), "%.*s/ps5-bt-sync.json",
                 (int)(slash - boot_file_path), boot_file_path);
  if (ret < 0 || (size_t)ret >= sizeof(output_path))
    return -1;
  ret = snprintf(temporary_path, sizeof(temporary_path), "%s.tmp", output_path);
  if (ret < 0 || (size_t)ret >= sizeof(temporary_path))
    return -1;
  if ((unlink(output_path) < 0 && errno != ENOENT) ||
      (unlink(temporary_path) < 0 && errno != ENOENT))
    return -1;

  for (unsigned i = 0; i < BT_SLOT_COUNT; i++) {
    if (sceRegMgrGetBin(BT_INFO_KEY + i * 0x10000L, slots[i], BT_SLOT_SIZE)) {
      memset(slots, 0, sizeof(slots));
      return -1;
    }
  }

  int fd = open(temporary_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) {
    memset(slots, 0, sizeof(slots));
    return -1;
  }
  FILE *out = fdopen(fd, "w");
  if (!out) {
    close(fd);
    unlink(temporary_path);
    memset(slots, 0, sizeof(slots));
    return -1;
  }
  fputs("{\"version\":2,\"adapter\":null,\"devices\":[", out);

  for (unsigned i = 0; i < BT_SLOT_COUNT; i++) {
    const uint8_t *info = slots[i];
    unsigned key = 0, key_nonff = 0, address = 0, address_nonff = 0;
    unsigned device_class = info[8] | (info[9] << 8) | (info[10] << 16);
    size_t name_size = strnlen((const char *)info + 128, 128);
    int valid_name = name_size > 0 && name_size < 128;

    // Removed bonds retain their keys but clear this flag.
    if (!(info[32] & 0x40))
      continue;
    for (int j = 16; j < 32; j++) {
      key |= info[j];
      key_nonff |= info[j] ^ 255;
    }
    for (int j = 0; j < 6; j++) {
      address |= info[j];
      address_nonff |= info[j] ^ 255;
    }
    for (size_t j = 0; j < name_size; j++)
      valid_name &= info[128 + j] >= 32 && info[128 + j] != 127;
    if (info[6] || info[7] || !key || !key_nonff || !address ||
        !address_nonff || !device_class || !valid_name) {
      skipped++;
      continue;
    }
    if (count++)
      fputc(',', out);
    fprintf(out, "{\"peer\":\"%02X:%02X:%02X:%02X:%02X:%02X\",\"name\":",
            info[5], info[4], info[3], info[2], info[1], info[0]);
    write_name(out, info + 128, name_size);
    fprintf(out, ",\"type\":4,\"class\":%u,\"key\":\"", device_class);
    for (int j = 16; j < 32; j++)
      fprintf(out, "%02X", info[j]);
    fputs("\"}", out);
  }
  fprintf(out, "],\"skipped\":%u}\n", skipped);
  memset(slots, 0, sizeof(slots));
  int failed = ferror(out);
  if (fflush(out) || fsync(fd))
    failed = 1;
  if (fclose(out))
    failed = 1;
  if (failed || rename(temporary_path, output_path)) {
    unlink(temporary_path);
    return -1;
  }
  return 0;
}
