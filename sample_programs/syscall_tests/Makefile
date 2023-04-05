include ../common.mk

# Add more test suites if needed.
FS_TEST		?= fs.c
FS_OBJ		?= $(OUTPUT_PATH)/fs


.phony: all clean

all: $(FS_OBJ)

$(FS_OBJ): $(FS_TEST)
	@$(CC) -o $@ $^ $(C_FLAGS) $(LINK) $(INCLUDE)

clean:
	@echo "Nothing to do"
