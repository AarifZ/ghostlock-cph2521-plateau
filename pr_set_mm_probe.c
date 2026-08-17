#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/prctl.h>
#include <linux/prctl.h>
#ifndef PR_SET_MM
#define PR_SET_MM 35
#endif
#ifndef PR_SET_MM_MAP
#define PR_SET_MM_MAP 14
#endif
#ifndef PR_SET_MM_MAP_SIZE
#define PR_SET_MM_MAP_SIZE 15
#endif
int main(void) {
  unsigned int sz = 0;
  errno = 0;
  long r = prctl(PR_SET_MM, PR_SET_MM_MAP_SIZE, (unsigned long)&sz, 0, 0);
  printf("MAP_SIZE: r=%ld errno=%d (%s) size=%u\n", r, errno, strerror(errno), sz);

  /* Also try a dummy MAP with zeroed struct to see EPERM vs EINVAL vs EFAULT */
  struct {
    unsigned long long start_code, end_code, start_data, end_data;
    unsigned long long start_brk, brk, start_stack;
    unsigned long long arg_start, arg_end, env_start, env_end;
    unsigned long long *auxv;
    unsigned int auxv_size;
    unsigned int exe_fd;
  } map;
  memset(&map, 0, sizeof(map));
  map.exe_fd = (unsigned int)-1;
  errno = 0;
  r = prctl(PR_SET_MM, PR_SET_MM_MAP, (unsigned long)&map, sizeof(map), 0);
  printf("MAP empty: r=%ld errno=%d (%s)\n", r, errno, strerror(errno));

  /* CAP_SYS_RESOURCE style single field without checkpoint path */
  errno = 0;
  r = prctl(PR_SET_MM, 1 /* START_CODE */, 0x10000, 0, 0);
  printf("START_CODE: r=%ld errno=%d (%s)\n", r, errno, strerror(errno));
  return 0;
}
