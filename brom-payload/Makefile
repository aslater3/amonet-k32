# Makefile for Region 15 clearing payload
#
# This builds a minimal BROM payload that clears EMI MPU Region 15
# before TEE/ATF can lock it.
#
# Target: Amazon Echo 2nd Gen (radar_puffin), MediaTek MT8163

# Toolchain
CC := arm-none-eabi-gcc
AS := arm-none-eabi-as
LD := arm-none-eabi-gcc
OBJCOPY := arm-none-eabi-objcopy

# Output directory
BUILD_DIR := build

# Compiler flags
CFLAGS := -std=gnu99 -Os -mthumb -mcpu=cortex-a9 -fno-builtin-printf -fno-strict-aliasing -fno-builtin-memcpy -fPIE -mno-unaligned-access -Wall -Wextra

# Linker flags
LDFLAGS := -nodefaultlibs -nostdlib -Wl,--build-id=none

# Source files
SOURCES := clear_region15.c start.S
OBJECTS := $(BUILD_DIR)/clear_region15.o $(BUILD_DIR)/start.o

# Default target
all: $(BUILD_DIR)/clear_region15.bin

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Compile C source
$(BUILD_DIR)/clear_region15.o: clear_region15.c | $(BUILD_DIR)
	$(CC) -c -o $@ $< $(CFLAGS)

# Assemble startup code
$(BUILD_DIR)/start.o: start.S | $(BUILD_DIR)
	$(AS) -o $@ $<

# Link object files
$(BUILD_DIR)/clear_region15.elf: $(OBJECTS) clear_region15.ld
	$(LD) -o $@ $(OBJECTS) $(LDFLAGS) -T clear_region15.ld

# Generate binary
$(BUILD_DIR)/clear_region15.bin: $(BUILD_DIR)/clear_region15.elf
	$(OBJCOPY) -O binary $^ $@
	@echo "Built: $@"
	@ls -lh $@

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean
