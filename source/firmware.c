#include "firmware.h"
#include "utils.h"
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PS5_WIFI_FW_BOOT_PATH "lib/nxp/pcieuartiw620_combo_v1.bin"
#define PS5_PRO_GPU_FW_BOOT_PATH_BASE "lib/firmware/amdgpu/viola"

// An amdgpu firmware file is a 0x100-byte driver header followed by the ucode
// array: a 0x100-byte $PS1 header, the payload and a 0x100-byte signature
// slot. The PS5 keeps only the payload, so the rest is rebuilt with the $PS1
// header reduced to its magic and payload size and the signature left blank.
#define AMDGPU_FW_HEADER_SIZE 0x100
#define PS1_HEADER_SIZE 0x100
#define PS1_SIGNATURE_SIZE 0x100

// Offset of the payload in a dumped file.
#define GPU_FIRMWARE_PAYLOAD_OFFSET (AMDGPU_FW_HEADER_SIZE + PS1_HEADER_SIZE)

#define AMDGPU_FW_MAX_PAYLOAD_DWORDS                                           \
  ((UINT32_MAX - AMDGPU_FW_HEADER_SIZE - PS1_HEADER_SIZE -                     \
    PS1_SIGNATURE_SIZE) /                                                      \
   sizeof(uint32_t))

// sizeof(struct rlc_firmware_header_v2_0) in amdgpu_ucode.h. Every field past
// the common header stays zero.
#define AMDGPU_RLC_HEADER_V2_0_SIZE 0x68

#define ARRAY_COUNT(a) (sizeof(a) / sizeof((a)[0]))

// A kernel GPU firmware table entry. The table at PS5_PRO_GPU_FW_OFFSET is an
// array of pointers to these.
struct gpu_firmware_blob_header {
  uint64_t size;      // payload length in dwords
  uint64_t tagString; // kernel VA
  uint64_t unknown1;  // ucode feature version: rlc 0x1, sdma 0x32, cp 0x1c
  uint64_t imagePtr;  // kernel VA
  uint32_t jtOffset;  // jump table start, dwords into the payload
  uint32_t jtSize;    // jump table length in dwords
  uint32_t unknown2;  // 0
  uint32_t checksum;  // rlc: xor of payload dwords, sdma: sum, cp: unknown
};

// Layouts from the Linux amdgpu driver's amdgpu_ucode.h.
struct amdgpu_common_firmware_header {
  uint32_t size_bytes;
  uint32_t header_size_bytes;
  uint16_t header_version_major;
  uint16_t header_version_minor;
  uint16_t ip_version_major;
  uint16_t ip_version_minor;
  uint32_t ucode_version;
  uint32_t ucode_size_bytes;
  uint32_t ucode_array_offset_bytes;
  uint32_t crc32;
};

struct amdgpu_gfx_firmware_header_v1_0 {
  struct amdgpu_common_firmware_header header;
  uint32_t ucode_feature_version;
  uint32_t jt_offset;
  uint32_t jt_size;
};

struct amdgpu_sdma_firmware_header_v1_0 {
  struct amdgpu_common_firmware_header header;
  uint32_t ucode_feature_version;
  uint32_t ucode_change_version;
  uint32_t jt_offset;
  uint32_t jt_size;
};

union amdgpu_firmware_header {
  struct amdgpu_common_firmware_header common;
  struct amdgpu_gfx_firmware_header_v1_0 gfx;
  struct amdgpu_sdma_firmware_header_v1_0 sdma;
  uint8_t raw[AMDGPU_FW_HEADER_SIZE];
};

enum gpu_firmware_kind { GPU_FW_RLC, GPU_FW_GFX, GPU_FW_SDMA };

struct gpu_firmware_blob_info {
  const char *name;
  enum gpu_firmware_kind kind;
  uint32_t ucode_version;
  uint32_t feature_version;
};

// Byte changes made to dumped files, at offsets into the file. A patch is
// only applied when the payload still holds its original bytes.
struct gpu_firmware_patch {
  const char *name;
  uint32_t file_offset;
  uint8_t from[4];
  uint8_t to[4];
};

// In kernel table order. The kernel does not keep ucode versions, so the
// versions are those of the cyan_skillfish2 firmware in linux-firmware
// (AMD 21.50)
static const struct gpu_firmware_blob_info gpu_firmware_blobs[] = {
    {"rlc", GPU_FW_RLC, 0xd, 0},        {"sdma", GPU_FW_SDMA, 0x34, 0x32},
    {"sdma1", GPU_FW_SDMA, 0x34, 0x32}, {"ce", GPU_FW_GFX, 0x25, 0x20},
    {"pfp", GPU_FW_GFX, 0x94, 0x20},    {"me", GPU_FW_GFX, 0x63, 0x20},
    {"mec", GPU_FW_GFX, 0x90, 0x20},    {"mec2", GPU_FW_GFX, 0x90, 0x20}};

static const struct gpu_firmware_patch gpu_firmware_patches[] = {
    // Viola checks bit 23 of indirect buffer packets. It does something weird
    // (likely proprietary) when it finds it set, causing a hang. Cyan Skillfish
    // ignores it. This patch just forces Viola to ignore it too, avoiding the
    // hang.
    {"pfp", 0x18b8, {0x63, 0x00, 0xc0, 0x96}, {0x11, 0x06, 0x00, 0x80}},
};

static size_t ps5_wifi_firmware_size(void) {
  return (size_t)env_offset.PS5_WIFI_FW_SIZE;
}

static uint64_t ps5_wifi_firmware_va(void) {
  return get_offset_va(env_offset.PS5_WIFI_FW_OFFSET);
}

// The table is an array of pointers to gpu_firmware_blob_header.
static uint64_t ps5_pro_gpu_firmware_table_slot_va(size_t index) {
  return get_offset_va(env_offset.PS5_PRO_GPU_FW_OFFSET) +
         index * sizeof(uint64_t);
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

static int build_boot_dir(const char *boot_file_path, char *boot_dir,
                          size_t boot_dir_size) {
  const char *slash = strrchr(boot_file_path, '/');
  int ret;

  if (slash == NULL)
    return -1;

  ret = snprintf(boot_dir, boot_dir_size, "%.*s", (int)(slash - boot_file_path),
                 boot_file_path);
  if (ret < 0 || (size_t)ret >= boot_dir_size)
    return -1;

  return 0;
}

static int build_firmware_path(const char *boot_file_path, char *boot_dir,
                               size_t boot_dir_size, char *fw_path,
                               size_t fw_path_size,
                               const char *file_leaf_name) {
  int ret;

  if (build_boot_dir(boot_file_path, boot_dir, boot_dir_size) < 0)
    return -1;

  ret =
      snprintf(fw_path, fw_path_size, "%s/%s", boot_dir, file_leaf_name);
  if (ret < 0 || (size_t)ret >= fw_path_size)
    return -1;

  return 0;
}

// Creates every directory component of file_leaf_name under boot_dir.
static int create_firmware_dirs(const char *boot_dir,
                                const char *file_leaf_name) {
  char path[512];
  const char *slash = file_leaf_name;
  int ret;

  while ((slash = strchr(slash, '/')) != NULL) {
    ret = snprintf(path, sizeof(path), "%s/%.*s", boot_dir,
                   (int)(slash - file_leaf_name), file_leaf_name);
    if (ret < 0 || (size_t)ret >= sizeof(path))
      return -1;
    if (mkdir_if_needed(path) < 0)
      return -1;
    slash++;
  }

  return 0;
}

static uint32_t crc32_update(uint32_t crc, const uint8_t *buf, size_t len) {
  crc = ~crc;
  while (len--) {
    crc ^= *buf++;
    for (int i = 0; i < 8; i++)
      crc = (crc >> 1) ^ (0xedb88320u & -(crc & 1));
  }
  return ~crc;
}

static void build_ps1_header(uint8_t *out, uint32_t payload_size) {
  memset(out, 0, PS1_HEADER_SIZE);
  memcpy(out + 0x10, "$PS1", 4);
  memcpy(out + 0x14, &payload_size, sizeof(payload_size));
}

static void build_amdgpu_header(union amdgpu_firmware_header *out,
                                const struct gpu_firmware_blob_info *info,
                                const struct gpu_firmware_blob_header *blob,
                                uint32_t crc) {
  uint32_t ucode_size = (uint32_t)blob->size * sizeof(uint32_t) +
                        PS1_HEADER_SIZE + PS1_SIGNATURE_SIZE;

  memset(out, 0, sizeof(*out));
  out->common.size_bytes = AMDGPU_FW_HEADER_SIZE + ucode_size;
  out->common.ucode_version = info->ucode_version;
  out->common.ucode_size_bytes = ucode_size;
  out->common.ucode_array_offset_bytes = AMDGPU_FW_HEADER_SIZE;
  out->common.crc32 = crc;

  switch (info->kind) {
  case GPU_FW_RLC:
    out->common.header_size_bytes = AMDGPU_RLC_HEADER_V2_0_SIZE;
    out->common.header_version_major = 2;
    out->common.ip_version_major = 10;
    out->common.ip_version_minor = 1;
    break;
  case GPU_FW_GFX:
    out->common.header_size_bytes = sizeof(out->gfx);
    out->common.header_version_major = 1;
    out->common.ip_version_major = 10;
    out->common.ip_version_minor = 1;
    out->gfx.ucode_feature_version = info->feature_version;
    out->gfx.jt_offset = blob->jtOffset;
    out->gfx.jt_size = blob->jtSize;
    break;
  case GPU_FW_SDMA:
    out->common.header_size_bytes = sizeof(out->sdma);
    out->common.header_version_major = 1;
    out->common.ip_version_major = 5;
    out->common.ip_version_minor = 0;
    out->sdma.ucode_feature_version = info->feature_version;
    out->sdma.jt_offset = blob->jtOffset;
    out->sdma.jt_size = blob->jtSize;
    break;
  }
}

// Sets apply[i] for each patch that targets this blob and whose original bytes
// are still in its payload.
static void select_gpu_firmware_patches(
    const char *name, const struct gpu_firmware_blob_header *hdr,
    uint64_t payload_size, int *apply) {
  for (size_t i = 0; i < ARRAY_COUNT(gpu_firmware_patches); i++) {
    const struct gpu_firmware_patch *p = &gpu_firmware_patches[i];
    uint64_t off = (uint64_t)p->file_offset - GPU_FIRMWARE_PAYLOAD_OFFSET;
    uint8_t cur[sizeof(p->from)];

    apply[i] = 0;
    if (strcmp(p->name, name) != 0)
      continue;

    if (p->file_offset < GPU_FIRMWARE_PAYLOAD_OFFSET ||
        off + sizeof(cur) > payload_size) {
      notify("PS5 Pro GPU firmware %s is too short for the patch at %#x, "
             "not patched\n",
             name, p->file_offset);
      continue;
    }

    kread(hdr->imagePtr + off, cur, sizeof(cur));
    if (memcmp(cur, p->from, sizeof(cur)) != 0) {
      notify("PS5 Pro GPU firmware %s has unexpected bytes at %#x, not "
             "patched\n",
             name, p->file_offset);
      continue;
    }

    apply[i] = 1;
  }
}

// Applies the selected patches to a chunk of payload starting at chunk_off.
static void patch_gpu_firmware_chunk(const int *apply, uint8_t *buf,
                                     uint64_t chunk_off, size_t chunk_len) {
  for (size_t i = 0; i < ARRAY_COUNT(gpu_firmware_patches); i++) {
    const struct gpu_firmware_patch *p = &gpu_firmware_patches[i];
    uint64_t off = (uint64_t)p->file_offset - GPU_FIRMWARE_PAYLOAD_OFFSET;

    if (!apply[i])
      continue;

    for (size_t j = 0; j < sizeof(p->to); j++) {
      if (off + j >= chunk_off && off + j < chunk_off + chunk_len)
        buf[off + j - chunk_off] = p->to[j];
    }
  }
}

static int dump_ps5_pro_gpu_firmware_blob(const char *boot_dir, size_t index) {
  const struct gpu_firmware_blob_info *info = &gpu_firmware_blobs[index];
  int apply_patch[ARRAY_COUNT(gpu_firmware_patches)];
  struct gpu_firmware_blob_header hdr;
  union amdgpu_firmware_header fw_hdr;
  uint8_t ps1_hdr[PS1_HEADER_SIZE];
  char fw_path[512];
  uint8_t buf[0x4000];
  uint64_t hdr_va;
  uint64_t payload_size;
  uint32_t crc;
  int ret;
  int fd;

  ret = snprintf(fw_path, sizeof(fw_path), "%s/%s_%s.bin", boot_dir,
                 PS5_PRO_GPU_FW_BOOT_PATH_BASE, info->name);
  if (ret < 0 || (size_t)ret >= sizeof(fw_path)) {
    notify("PS5 Pro GPU firmware dump path is too long\n");
    return -1;
  }

  kread(ps5_pro_gpu_firmware_table_slot_va(index), &hdr_va, sizeof(hdr_va));
  if (hdr_va == 0) {
    notify("PS5 Pro GPU firmware header pointer for %s is null\n", info->name);
    return -1;
  }

  kread(hdr_va, &hdr, sizeof(hdr));
  if (hdr.size == 0 || hdr.imagePtr == 0) {
    notify("PS5 Pro GPU firmware header for %s is empty\n", info->name);
    return -1;
  }

  if (hdr.size > AMDGPU_FW_MAX_PAYLOAD_DWORDS ||
      (uint64_t)hdr.jtOffset + hdr.jtSize > hdr.size) {
    notify("PS5 Pro GPU firmware header for %s is malformed\n", info->name);
    return -1;
  }

  payload_size = hdr.size * sizeof(uint32_t);
  select_gpu_firmware_patches(info->name, &hdr, payload_size, apply_patch);

  fd = open(fw_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0) {
    notify("Could not create PS5 Pro GPU firmware file %s\n", fw_path);
    return -1;
  }

  // The driver header holds the crc of everything after it, so a blank one
  // goes first and is filled in once the rest is written.
  memset(&fw_hdr, 0, sizeof(fw_hdr));
  build_ps1_header(ps1_hdr, (uint32_t)payload_size);
  crc = crc32_update(0, ps1_hdr, sizeof(ps1_hdr));
  if (write_all(fd, &fw_hdr, sizeof(fw_hdr)) < 0 ||
      write_all(fd, ps1_hdr, sizeof(ps1_hdr)) < 0)
    goto write_failed;

  for (uint64_t copied = 0; copied < payload_size; copied += sizeof(buf)) {
    size_t chunk = payload_size - copied;
    if (chunk > sizeof(buf))
      chunk = sizeof(buf);

    kread(hdr.imagePtr + copied, buf, chunk);
    patch_gpu_firmware_chunk(apply_patch, buf, copied, chunk);
    crc = crc32_update(crc, buf, chunk);
    if (write_all(fd, buf, chunk) < 0)
      goto write_failed;
  }

  memset(buf, 0, PS1_SIGNATURE_SIZE);
  crc = crc32_update(crc, buf, PS1_SIGNATURE_SIZE);
  build_amdgpu_header(&fw_hdr, info, &hdr, crc);
  if (write_all(fd, buf, PS1_SIGNATURE_SIZE) < 0 ||
      lseek(fd, 0, SEEK_SET) < 0 ||
      write_all(fd, &fw_hdr, sizeof(fw_hdr)) < 0)
    goto write_failed;

  close(fd);
  notify("Dumped PS5 Pro GPU firmware %s to %s (%llu bytes)\n", info->name,
         fw_path, (unsigned long long)fw_hdr.common.size_bytes);
  return 0;

write_failed:
  close(fd);
  notify("Could not write PS5 Pro GPU firmware file %s\n", fw_path);
  return -1;
}

static int dump_ps5_pro_gpu_firmware(const char *boot_file_path) {
  char boot_dir[512];

  if (build_boot_dir(boot_file_path, boot_dir, sizeof(boot_dir)) < 0) {
    notify("PS5 Pro GPU firmware dump path is too long\n");
    return -1;
  }

  if (create_firmware_dirs(boot_dir, PS5_PRO_GPU_FW_BOOT_PATH_BASE) < 0) {
    notify("Could not create PS5 Pro GPU firmware directory under %s\n",
           boot_dir);
    return -1;
  }

  for (size_t i = 0; i < ARRAY_COUNT(gpu_firmware_blobs); i++) {
    if (dump_ps5_pro_gpu_firmware_blob(boot_dir, i) < 0)
      return -1;
  }

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
    notify("PS5 WiFi firmware offset missing for firmware %04x\n", fw);
    return -1;
  }

  if (build_firmware_path(boot_file_path, boot_dir, sizeof(boot_dir), fw_path,
                          sizeof(fw_path), PS5_WIFI_FW_BOOT_PATH) < 0) {
    notify("PS5 WiFi firmware dump path is too long\n");
    return -1;
  }

  if (create_firmware_dirs(boot_dir, PS5_WIFI_FW_BOOT_PATH) < 0) {
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
  int ret = dump_ps5_wifi_firmware(boot_file_path);

  // Only PS5 Pro firmwares have a GPU firmware table offset.
  if (env_offset.PS5_PRO_GPU_FW_OFFSET != 0 &&
      dump_ps5_pro_gpu_firmware(boot_file_path) < 0)
    ret = -1;

  return ret;
}
