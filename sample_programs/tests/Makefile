include ../common.mk

# Add more test suites if needed.
FS_TEST			?= fs.c
MALLOC_TEST		?= malloc.c
FS_OBJ			?= $(OUTPUT_PATH)/fs
MALLOC_OBJ		?= $(OUTPUT_PATH)/malloc

.phony: all clean

all: $(FS_OBJ) $(MALLOC_OBJ) $(DYLIB_OBJ) $(DYLIB_DEPDENDEE_OBJ)

$(FS_OBJ): $(FS_TEST)
	@$(CC) -o $@ $^ $(C_FLAGS) $(LINK) $(INCLUDE)

$(MALLOC_OBJ): $(MALLOC_TEST)
	@$(CC) -o $@ $^ $(C_FLAGS) $(LINK) $(INCLUDE)

clean:
	@echo "Nothing to do"
