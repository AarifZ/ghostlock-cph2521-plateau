API ?= 35

NDK_ROOT ?= $(or $(ANDROID_NDK_HOME),$(ANDROID_NDK_ROOT))
ifeq ($(OS),Windows_NT)
  NDK_CC := $(NDK_ROOT)/toolchains/llvm/prebuilt/windows-x86_64/bin/aarch64-linux-android$(API)-clang
else
  NDK_CC := $(NDK_ROOT)/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android$(API)-clang
endif

SRCS := \
  src/core/main.c \
  src/core/util.c \
  src/core/slide.c \
  src/core/fops.c \
  src/core/pipe_physrw.c \
  src/core/root.c \
  src/core/miniadb.c \
  src/core/umh_root.c

CFLAGS := -O2 -Wall -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function \
  -Isrc/core -Isrc/devices -DTARGET_CONFIG_H=\"target.h\" \
  -DGHOSTLOCK_KERNEL_5_10 -DKIMAGE_TEXT_BASE=0xffffffc008000000ULL
LDFLAGS := -fPIE -pie -pthread

# CPH2521 defines baked into CFLAGS (2026-09-13, recovered from the shipped
# binary + device logs): without GHOSTLOCK_KERNEL_5_10 the whole 5.10
# stamp/route code compiles OUT (~214KB binary, no SLIDE_CRED strings, the
# fire would be a dud). KIMAGE_TEXT_BASE must be the CPH2521 link address
# (kaslr_base=KIMAGE=ffffffc008000000 in every device fire log).

.PHONY: all clean

all: ghostlock

ghostlock: $(SRCS)
	$(NDK_CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

clean:
	rm -f ghostlock
