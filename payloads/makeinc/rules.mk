ifeq ($V, 1)
	VERBOSE =
else
	VERBOSE = @
endif

include ../makeinc/config.mk

OBJ := $(SRC:%.c=build/%.o)
OBJ += $(SRC_ASM:%.S=build/%.o)
DEP := $(OBJ:%.o=%.d)
INC := -I..

all: $(TARGET).ihex $(TARGET).bin | build

.PHONY: clean all
.SUFFIXES:

-include $(DEP)

build:
	@mkdir -p build

build/%.o: %.S
	@echo cc $<
	@mkdir -p $(dir $@)
	$(VERBOSE) $(ENV) $(CC) $(CFLAGS) $(CFLAGS_OPT) $(INC) $(DEF) -MMD -MT $@ -MF build/$*.d -o $@ -c $<

build/%.o: %.c
	@echo cc $<
	@mkdir -p $(dir $@)
	$(VERBOSE) $(ENV) $(CC) $(CFLAGS) $(CFLAGS_OPT) $(INC) $(DEF) -MMD -MT $@ -MF build/$*.d -o $@ -c $<

$(TARGET).sym: $(OBJ)
	@echo ld $(notdir $@)
	$(VERBOSE) $(ENV) $(LD) $(LDFLAGS) -o $@ $(OBJ) $(LDLIBS)

$(TARGET): $(TARGET).sym
	@echo strip $(notdir $@)
	$(VERBOSE) $(ENV) $(STRIP) $(TARGET).sym -o $@

$(TARGET).bin: $(TARGET)
	@echo objcopy $(notdir $@)
	$(VERBOSE) $(ENV) $(OBJCOPY) -O binary $(TARGET) $@

$(TARGET).ihex: $(TARGET)
	@echo objcopy $(notdir $@)
	$(VERBOSE) $(ENV) $(OBJCOPY) -O ihex $(TARGET) $@

clean:
	@rm -rf build lib
