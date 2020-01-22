CC := clang
LD :=  arm-none-eabi-ld
STRIP := arm-none-eabi-strip
OBJCOPY := arm-none-eabi-objcopy

CFLAGS_OPT := \
    -Os

CFLAGS := \
    -std=c11 \
    -ffreestanding \
    -fno-builtin \
    -Wall \
    -mcpu=cortex-r4 \
    -DGDBSTUB_PRINT \
    -I../lib \
    -frwpi \
    -fropi \
    -mbig-endian \
	-target arm-none-eabi
LDFLAGS := \
    -EB \
    -Tlink.ld \
    -nostdlib \
    --gc-sections \
    -nostartfiles

ifeq ($(FW_VER),)
FW_VER := 2
endif

CFLAGS += -DFW_VER=$(FW_VER)
