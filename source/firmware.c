#include "firmware.h"
#include "utils.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>

#define PS5_WIFI_FW_BOOT_PATH "lib/nxp/pcieuartiw620_combo_v1.bin"

static size_t ps5_wifi_firmware_size(void) {
  return (size_t)env_offset.PS5_WIFI_FW_SIZE;
}

static uint64_t ps5_wifi_firmware_va(void) {
  return get_offset_va(env_offset.PS5_WIFI_FW_OFFSET);
}

static int write_all(int fd, const void *buf, size_t len) {
  size_t written = 0;

  while (written < len) {
    ssize_t ret = write(fd, (const uint8_t *)buf + written, len - written);
    if (ret < 0)
      return -1;
    if (ret == 0)
      return -1;
    written += (size_t)ret;
  }

  return 0;
}

static int mkdir_if_needed(const char *path) {
  struct stat st;

  if (mkdir(path, 0777) == 0)
    return 0;

  if (errno != EEXIST)
    return -1;

  if (stat(path, &st) < 0)
    return -1;

  return S_ISDIR(st.st_mode) ? 0 : -1;
}

static int build_firmware_path(const char *boot_file_path, char *boot_dir,
                               size_t boot_dir_size, char *fw_path,
                               size_t fw_path_size) {
  const char *slash = strrchr(boot_file_path, '/');
  int ret;

  if (slash == NULL)
    return -1;

  ret = snprintf(boot_dir, boot_dir_size, "%.*s", (int)(slash - boot_file_path),
                 boot_file_path);
  if (ret < 0 || (size_t)ret >= boot_dir_size)
    return -1;

  ret =
      snprintf(fw_path, fw_path_size, "%s/%s", boot_dir, PS5_WIFI_FW_BOOT_PATH);
  if (ret < 0 || (size_t)ret >= fw_path_size)
    return -1;

  return 0;
}

static int create_firmware_dirs(const char *boot_dir) {
  char path[512];
  int ret;

  ret = snprintf(path, sizeof(path), "%s/lib", boot_dir);
  if (ret < 0 || (size_t)ret >= sizeof(path))
    return -1;
  if (mkdir_if_needed(path) < 0)
    return -1;

  ret = snprintf(path, sizeof(path), "%s/lib/nxp", boot_dir);
  if (ret < 0 || (size_t)ret >= sizeof(path))
    return -1;
  if (mkdir_if_needed(path) < 0)
    return -1;

  return 0;
}

static int dump_ps5_wifi_firmware(const char *boot_file_path) {
  char boot_dir[512];
  char fw_path[512];
  uint8_t buf[0x4000];
  uint64_t fw_va;
  size_t fw_size;
  int fd;

  if (env_offset.PS5_WIFI_FW_OFFSET == 0 || env_offset.PS5_WIFI_FW_SIZE == 0) {
    notify("PS5 WiFi firmware dump skipped (no offset for fw %04x) - benign; "
           "Linux just won't have the wifi blob. Not an error.\n", fw);
    return 0;  /* benign skip: do NOT report as failure (avoids the misleading */
               /* "Something went wrong while dumping device firmwares" line) */
  }

  if (build_firmware_path(boot_file_path, boot_dir, sizeof(boot_dir), fw_path,
                          sizeof(fw_path)) < 0) {
    notify("PS5 WiFi firmware dump path is too long\n");
    return -1;
  }

  if (create_firmware_dirs(boot_dir) < 0) {
    notify("Could not create PS5 WiFi firmware directory under %s\n", boot_dir);
    return -1;
  }

  fd = open(fw_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0) {
    notify("Could not create PS5 WiFi firmware file %s\n", fw_path);
    return -1;
  }

  fw_va = ps5_wifi_firmware_va();
  fw_size = ps5_wifi_firmware_size();
  for (size_t copied = 0; copied < fw_size; copied += sizeof(buf)) {
    size_t chunk = fw_size - copied;
    if (chunk > sizeof(buf))
      chunk = sizeof(buf);

    kread(fw_va + copied, buf, chunk);
    if (write_all(fd, buf, chunk) < 0) {
      close(fd);
      notify("Could not write PS5 WiFi firmware file %s\n", fw_path);
      return -1;
    }
  }

  close(fd);
  notify("Dumped PS5 WiFi firmware to %s (%llu bytes)\n", fw_path,
         (unsigned long long)fw_size);
  return 0;
}

int dump_device_firmwares(const char *boot_file_path) {
  return dump_ps5_wifi_firmware(boot_file_path);
}
