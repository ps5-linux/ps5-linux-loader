#include "loader.h"
#include "config.h"
#include "firmware.h"
#include "linux.h"
#include "utils.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>

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
        // make sure the last string is null-terminated
        overrides_start[size] = 0;
      }
    }
  }

  // overrides not found, or unreadable, or currently looking for it
  if (state == 1)
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
      notify("File '%s' found in '%s' - rmux was here\n", filename,
             file_paths[i]);
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
  char bzimage_path[256];
  char initrd_path[256];

  size_t bzimage_size = find_and_get_size_of_file("bzImage", bzimage_path);
  if (bzimage_size < 0) {
    notify("File bzImage not found at default paths - Aborting\n");
    return -1;
  }

  void *bzimage =
      mmap(NULL, ALIGN_UP(bzimage_size, PAGE_SIZE), PROT_READ | PROT_WRITE,
           MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (bzimage == MAP_FAILED) {
    notify("[-] Error could not allocate bzimage.\n");
    return -1;
  }

  bzimage_size =
      read_file(bzimage_path, bzimage, ALIGN_UP(bzimage_size, PAGE_SIZE));
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
      mmap(NULL, ALIGN_UP(initrd_size, PAGE_SIZE), PROT_READ | PROT_WRITE,
           MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (initrd == MAP_FAILED) {
    notify("[-] Error could not allocate initrd.\n");
    return -1;
  }

  initrd_size =
      read_file(initrd_path, initrd, ALIGN_UP(initrd_size, PAGE_SIZE));
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
  info->kit_type = (int)get_kit_type();
  strcpy(info->cmdline, cmdline);

  uint64_t page = alloc_page();
  kwrite(pa_to_dmap(page), info, sizeof(struct linux_info));
  install_page_syscore(kernel_cave_linux_info, page, 0);

  for (int i = 0; i < bzimage_size; i += PAGE_SIZE) {
    install_page_syscore(info->bzimage + i,
                         vtophys_user((uintptr_t)bzimage + i), 0);
  }

  for (int i = 0; i < initrd_size; i += PAGE_SIZE) {
    install_page_syscore(info->initrd + i, vtophys_user((uintptr_t)initrd + i),
                         0);
  }

  return 0;
}
