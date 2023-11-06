BUILD_DIR = ./build
INCLUDE := include

OBJS = $(BUILD_DIR)/main.o $(BUILD_DIR)/linker.o $(BUILD_DIR)/hashmap.o

$(BUILD_DIR)/main.o: main.c
	gcc -I$(INCLUDE) -c -o $@ $^

$(BUILD_DIR)/linker.o: linker.c
	gcc -I$(INCLUDE) -c -o $@ $^

$(BUILD_DIR)/hashmap.o: hashmap.c
	gcc -I$(INCLUDE) -c -o $@ $^

$(BUILD_DIR)/analyze-bpf: $(OBJS)
	gcc $^ -o $@ -lelf

clean:
	cd $(BUILD_DIR) && rm -rf ./*

build_dir:
	mkdir -p $(BUILD_DIR)

build: $(BUILD_DIR)/analyze-bpf

all: clean build_dir build
