#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define KGSL_IOC_TYPE 0x09
struct kgsl_device_getproperty {
  unsigned int type;
  void *value;
  size_t sizebytes;
};
#define IOCTL_KGSL_DEVICE_GETPROPERTY _IOWR(KGSL_IOC_TYPE, 0x2, struct kgsl_device_getproperty)

int main(void) {
  int fd = open("/dev/kgsl-3d0", O_RDWR);
  printf("kgsl fd=%d errno=%d\n", fd, errno);
  if (fd < 0)
    return 1;
  unsigned int types[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0x11, 0x12, 0x13, 0x20};
  unsigned char buf[256];
  for (unsigned i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
    memset(buf, 0, sizeof(buf));
    struct kgsl_device_getproperty p;
    p.type = types[i];
    p.value = buf;
    p.sizebytes = 64;
    errno = 0;
    int r = ioctl(fd, IOCTL_KGSL_DEVICE_GETPROPERTY, &p);
    printf("prop 0x%x ret=%d errno=%d", types[i], r, errno);
    if (r == 0) {
      unsigned j;
      printf(" ");
      for (j = 0; j < 32; j++)
        printf("%02x", buf[j]);
      uint64_t *q = (uint64_t *)buf;
      unsigned k;
      for (k = 0; k < 4; k++) {
        if (q[k] >= 0xffffff8000000000ULL)
          printf(" KPTR[%u]=%016llx", k, (unsigned long long)q[k]);
      }
    }
    printf("\n");
  }
  close(fd);
  return 0;
}
