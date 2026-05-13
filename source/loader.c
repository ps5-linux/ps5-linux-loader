#include "loader.h"
#include "config.h"
#include "firmware.h"
#include "linux.h"
#include "utils.h"
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/cpuset.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define MINI_SYSCORE_PID 1

uint64_t alloc_page(void) {
  void *page = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_ANONYMOUS, -1, 0);

  // Fault it to force physical allocation
  *(uint8_t *)page = 0;

  return vtophys_user((uintptr_t)page);
}

void install_page(uintptr_t pml4, vm_offset_t va, vm_paddr_t pa, int bits) {
  uint64_t entry;

  uintptr_t pml4e = pml4 + pmap_pml4e_index(va) * 8;
  entry = kread64(pml4e);
  if (!PAGE_P(entry)) {
    uint64_t page = alloc_page();
    entry = page | PG_B_RW | PG_B_P | bits;
    kwrite64(pml4e, entry);
  }

  uintptr_t pdpe = pa_to_dmap(PAGE_PA(entry)) + pmap_pdpe_index(va) * 8;
  entry = kread64(pdpe);
  if (!(entry & PG_B_P)) {
    uint64_t page = alloc_page();
    entry = page | PG_B_RW | PG_B_P | bits;
    kwrite64(pdpe, entry);
  }

  uintptr_t pde = pa_to_dmap(PAGE_PA(entry)) + pmap_pde_index(va) * 8;
  entry = kread64(pde);
  if (!(entry & PG_B_P)) {
    uint64_t page = alloc_page();
    entry = page | PG_B_RW | PG_B_P | bits;
    kwrite64(pde, entry);
  }

  uintptr_t pte = pa_to_dmap(PAGE_PA(entry)) + pmap_pte_index(va) * 8;
  entry = pa | PG_B_RW | PG_B_P | bits;
  pte_store(pte, entry);
}

void pte_store(uintptr_t ptep, uint64_t pte) {
  static_assert((PAGE_SIZE % 0x1000) == 0,
                "PAGE_SIZE should be a multiple of 0x1000");

  for (uint64_t i = 0; i < (PAGE_SIZE / 0x1000); i++) {
    kwrite64(ptep + i * 8, pte + i * 0x1000);
  }
}

const char *file_paths[] = {
    "/mnt/usb0/",           "/mnt/usb1/",           "/mnt/usb2/",
    "/mnt/usb3/",           "/mnt/usb0/PS5/Linux/", "/mnt/usb1/PS5/Linux/",
    "/mnt/usb2/PS5/Linux/", "/mnt/usb3/PS5/Linux/",
};

long find_and_get_size_of_file(const char *filename, char *found_path);
int find_and_read_file(const char *filename, void *buf, size_t bufsize);

static const char *get_overridden_filename(const char *filename) {
  static int state = 0;
  static char *overrides_start = nullptr;
  static char *overrides_end = nullptr;

  if (state == 0) {
    state = 1;
    char found_path[256];
    ssize_t size = find_and_get_size_of_file("path-override.txt", found_path);
    if (size > 0) {
      overrides_start = malloc(size + 1);
      overrides_end = overrides_start + size + 1;
      if (read_file(found_path, overrides_start, size) == size) {
        state = 2;
        for (char *p = overrides_start; p < overrides_end; p++)
          if (*p == '\n')
            *p = 0;
        overrides_start[size] =
            0; // make sure the last string is null-terminated
      }
    }
  }

  if (state ==
      1) // overrides not found, or unreadable, or currently looking for it
    return filename;

  size_t needle_len = strlen(filename);
  for (const char *p = overrides_start; p < overrides_end;) {
    size_t haystack_len = strlen(p);
    if (haystack_len > needle_len && !strncmp(p, filename, needle_len) &&
        p[needle_len] == '=')
      return p + needle_len + 1;
    p += haystack_len + 1;
  }

  // haven't found an override, return original filename
  return filename;
}

long find_and_get_size_of_file(const char *filename, char *found_path) {
  char full_path[256];
  struct stat st;

  filename = get_overridden_filename(filename);
  int num_paths = sizeof(file_paths) / sizeof(file_paths[0]);

  for (int i = 0; i < num_paths; i++) {
    snprintf(full_path, sizeof(full_path), "%s%s", file_paths[i], filename);

    if (stat(full_path, &st) == 0) {
      notify("File '%s' found in '%s'\n", filename, file_paths[i]);
      strcpy(found_path, full_path);
      return st.st_size;
    }
  }

  return -1;
}

int find_and_read_file(const char *filename, void *buf, size_t bufsize) {
  char full_path[256];
  struct stat st;

  int num_paths = sizeof(file_paths) / sizeof(file_paths[0]);

  for (int i = 0; i < num_paths; i++) {
    snprintf(full_path, sizeof(full_path), "%s%s", file_paths[i], filename);

    if (stat(full_path, &st) == 0) {
      notify("File '%s' found in '%s'\n", filename, file_paths[i]);
      return read_file(full_path, buf, bufsize);
    }
  }

  return -1;
}

int read_file(const char *path, void *buf, size_t bufsize) {
  int fd = open(path, O_RDONLY);
  if (fd < 0)
    return fd;
  int r = read(fd, buf, bufsize);
  close(fd);
  return r;
}

void trim_newline(char *s) {
  while (*s != '\0') {
    if (*s == '\r' || *s == '\n') {
      *s = '\0';
      break;
    }
    s++;
  }
}

int fetch_linux(struct linux_info *info) {
  uintptr_t syscore_pmap = getpmap(kernel_get_proc(MINI_SYSCORE_PID));
  uintptr_t syscore_pml4 = kread64(syscore_pmap + 0x20);

  char bzimage_path[256];
  char initrd_path[256];

  size_t bzimage_size = find_and_get_size_of_file("bzImage", bzimage_path);
  if (bzimage_size < 0) {
    notify("File bzImage not found at default paths - Aborting\n");
    return -1;
  }

  void *bzimage =
      mmap(NULL, ALIGN_UP(bzimage_size, 0x1000), PROT_READ | PROT_WRITE,
           MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (bzimage == MAP_FAILED) {
    notify("[-] Error could not allocate bzimage.\n");
    return -1;
  }

  bzimage_size =
      read_file(bzimage_path, bzimage, ALIGN_UP(bzimage_size, 0x1000));
  if (bzimage_size < 0) {
    notify("Something went wrong while reading bzImage - Aborting\n");
    return -1;
  }

  size_t initrd_size = find_and_get_size_of_file("initrd.img", initrd_path);
  if (bzimage_size < 0) {
    notify("File bzImage not found at default paths - Aborting\n");
    return -1;
  }

  void *initrd =
      mmap(NULL, ALIGN_UP(initrd_size, 0x1000), PROT_READ | PROT_WRITE,
           MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (initrd == MAP_FAILED) {
    notify("[-] Error could not allocate initrd.\n");
    return -1;
  }

  initrd_size = read_file(initrd_path, initrd, ALIGN_UP(initrd_size, 0x1000));
  if (initrd_size < 0) {
    notify("Something went wrong while reading initrd - Aborting\n");
    return -1;
  }

  if (dump_device_firmwares(initrd_path) < 0) {
    notify(
        "Something went wrong while dumping device firmwares - Continuing\n");
  }

  size_t vram_size;
  char buf_vram[16] = {};
  int ret = find_and_read_file("vram.txt", buf_vram, sizeof(buf_vram) - 1);
  if (ret < 0) {
    printf(
        "File vram.txt not found at default paths - Using static fallback\n");
    vram_size = VRAM_SIZE;
  } else {
    trim_newline(buf_vram);
    vram_size = strtoull(buf_vram, NULL, 16);
    if (vram_size == 0) {
      printf("Seems like the configured vram value is wrong - Using static "
             "fallback\n");
      vram_size = VRAM_SIZE;
    }
  }

  char cmdline[2048] = {};
  ret = find_and_read_file("cmdline.txt", cmdline, sizeof(cmdline) - 1);
  if (ret < 0) {
    printf("File cmdline.txt not found at default paths - Using static "
           "fallback\n");
    strcpy(cmdline, CMD_LINE);
  } else {
    trim_newline(cmdline);
  }

  info->linux_info = kernel_cave_linux_info;
  info->bzimage = kernel_cave_bzImage;
  info->bzimage_size = bzimage_size;
  info->initrd = kernel_cave_bzImage + ALIGN_UP(bzimage_size, PAGE_SIZE);
  info->initrd_size = initrd_size;
  info->vram_size = vram_size;
  strcpy(info->cmdline, cmdline);
  info->kit_type = (int)get_kit_type();

  uint64_t page = alloc_page();
  kwrite(pa_to_dmap(page), info, sizeof(struct linux_info));
  install_page(syscore_pml4, kernel_cave_linux_info, page, 0);

  for (int i = 0; i < bzimage_size; i += PAGE_SIZE) {
    install_page(syscore_pml4, info->bzimage + i,
                 vtophys_user((uintptr_t)bzimage + i), 0);
  }

  for (int i = 0; i < initrd_size; i += PAGE_SIZE) {
    install_page(syscore_pml4, info->initrd + i,
                 vtophys_user((uintptr_t)initrd + i), 0);
  }

  return 0;
}
