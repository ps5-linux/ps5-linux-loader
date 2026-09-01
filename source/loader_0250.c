#include "loader_0250.h"
#include "config_0250.h"
#include "loader.h"
#include "staging_0250.h"
#include "utils.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

static int read_exact(const char *path, void *buffer, size_t size) {
  int fd = open(path, O_RDONLY);
  if (fd < 0)
    return -1;

  size_t done = 0;
  while (done < size) {
    ssize_t count = read(fd, (uint8_t *)buffer + done, size - done);
    if (count < 0 && errno == EINTR)
      continue;
    if (count <= 0) {
      close(fd);
      return -1;
    }
    done += (size_t)count;
  }
  close(fd);
  return 0;
}

static int load_small_file(const char *name, char *buffer, size_t capacity) {
  char path[256];
  long size = find_and_get_size_of_file(name, path);
  if (size <= 0 || (size_t)size >= capacity)
    return -1;
  if (read_exact(path, buffer, (size_t)size))
    return -1;
  buffer[size] = '\0';
  trim_newline(buffer);
  return 0;
}

static int recognized_initrd(const uint8_t *data, size_t size) {
  static const uint8_t gzip[] = {0x1F, 0x8B};
  static const uint8_t xz[] = {0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00};
  static const uint8_t zstd[] = {0x28, 0xB5, 0x2F, 0xFD};

  return (size >= sizeof(gzip) && !memcmp(data, gzip, sizeof(gzip))) ||
         (size >= sizeof(xz) && !memcmp(data, xz, sizeof(xz))) ||
         (size >= sizeof(zstd) && !memcmp(data, zstd, sizeof(zstd))) ||
         (size >= 6 &&
          (!memcmp(data, "070701", 6) || !memcmp(data, "070702", 6)));
}

static int map_buffer(uint64_t target, const void *source, size_t size) {
  for (size_t offset = 0; offset < size; offset += PAGE_SIZE) {
    uint64_t pa = staging_0250_user_pa((uint64_t)source + offset);
    if (!pa || staging_0250_map(target + offset, pa))
      return -1;
  }
  return 0;
}

int fetch_linux_0250(struct linux_info *info) {
  char bzimage_path[256];
  char initrd_path[256];
  long bzimage_file_size = find_and_get_size_of_file("bzImage", bzimage_path);
  long initrd_file_size = find_and_get_size_of_file("initrd.img", initrd_path);

  if (bzimage_file_size < 0x240 || bzimage_file_size > INT_MAX ||
      initrd_file_size <= 0 || initrd_file_size > INT_MAX) {
    notify("FW 2.50 requires valid bzImage and initrd.img files\n");
    return -1;
  }

  size_t bzimage_size = (size_t)bzimage_file_size;
  size_t initrd_size = (size_t)initrd_file_size;
  size_t bzimage_mapped = ALIGN_UP(bzimage_size, PAGE_SIZE);
  size_t initrd_mapped = ALIGN_UP(initrd_size, PAGE_SIZE);
  uint64_t capacity = hv_stack_floor - cave_bzImage;
  if (bzimage_mapped > capacity || initrd_mapped > capacity - bzimage_mapped) {
    notify("FW 2.50 Linux files exceed the reserved memory range\n");
    return -1;
  }

  void *bzimage = mmap(NULL, bzimage_mapped, PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  void *initrd = mmap(NULL, initrd_mapped, PROT_READ | PROT_WRITE,
                      MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (bzimage == MAP_FAILED || initrd == MAP_FAILED ||
      read_exact(bzimage_path, bzimage, bzimage_size) ||
      read_exact(initrd_path, initrd, initrd_size)) {
    if (bzimage != MAP_FAILED)
      munmap(bzimage, bzimage_mapped);
    if (initrd != MAP_FAILED)
      munmap(initrd, initrd_mapped);
    notify("FW 2.50 could not read the Linux files\n");
    return -1;
  }

  struct boot_params *params = bzimage;
  uint8_t setup_sects = params->hdr.setup_sects ? params->hdr.setup_sects : 4;
  size_t required =
      ((size_t)setup_sects + 1) * 512 + (size_t)params->hdr.syssize * 16;
  if (params->hdr.boot_flag != 0xAA55 || params->hdr.header != 0x53726448 ||
      params->hdr.version < 0x020C || !(params->hdr.loadflags & 1) ||
      (params->hdr.xloadflags & 3) != 3 || !params->hdr.init_size ||
      required > bzimage_size || !recognized_initrd(initrd, initrd_size)) {
    notify("FW 2.50 Linux files failed validation\n");
    return -1;
  }

  size_t vram_size = VRAM_SIZE;
  char vram[16] = {0};
  if (!load_small_file("vram.txt", vram, sizeof(vram))) {
    char *end = NULL;
    unsigned long long parsed = strtoull(vram, &end, 16);
    if (end && !*end && parsed >= 0x04000000ULL && parsed <= 0x40000000ULL &&
        !(parsed & 0x00FFFFFFULL))
      vram_size = (size_t)parsed;
  }

  char cmdline[2048] = {0};
  if (load_small_file("cmdline.txt", cmdline, sizeof(cmdline)))
    strcpy(cmdline, CMD_LINE);
  if (!cmdline[0] || (params->hdr.cmdline_size &&
                      strlen(cmdline) + 1 > params->hdr.cmdline_size)) {
    notify("FW 2.50 Linux command line is invalid\n");
    return -1;
  }

  *info = (struct linux_info){
      .linux_info = kernel_cave_linux_info,
      .bzimage = kernel_cave_bzImage,
      .bzimage_size = bzimage_size,
      .initrd = kernel_cave_bzImage + bzimage_mapped,
      .initrd_size = initrd_size,
      .vram_size = vram_size,
      .kit_type = (int)get_kit_type(),
  };
  strcpy(info->cmdline, cmdline);

  uint64_t info_pa = staging_0250_alloc_page();
  if (!info_pa) {
    notify("FW 2.50 could not allocate Linux metadata\n");
    return -1;
  }
  kernel_copyin(info, dmap + info_pa, sizeof(*info));
  struct linux_info readback = {0};
  if (kernel_copyout(dmap + info_pa, &readback, sizeof(readback)) ||
      memcmp(info, &readback, sizeof(readback)) ||
      staging_0250_map(info->linux_info, info_pa) ||
      map_buffer(info->bzimage, bzimage, bzimage_mapped) ||
      map_buffer(info->initrd, initrd, initrd_mapped)) {
    notify("FW 2.50 could not map the Linux files\n");
    return -1;
  }

  notify("PS5 device firmware extraction is not available on firmware 2.50\n");
  return 0;
}
