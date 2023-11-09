# analyze-bpftool
BUILD_DIR = ./build
INCLUDE := include

OBJS = $(BUILD_DIR)/main.o $(BUILD_DIR)/linker.o $(BUILD_DIR)/hashmap.o $(BUILD_DIR)/strset.o \
	$(BUILD_DIR)/btf.o $(BUILD_DIR)/libbpf.o $(BUILD_DIR)/gen.o

$(BUILD_DIR)/main.o: bpftool/main.c
	gcc -I$(INCLUDE) -c -o $@ $^

$(BUILD_DIR)/linker.o: linker.c
	gcc -I$(INCLUDE) -c -o $@ $^

$(BUILD_DIR)/hashmap.o: hashmap.c
	gcc -I$(INCLUDE) -c -o $@ $^

$(BUILD_DIR)/strset.o: strset.c
	gcc -I$(INCLUDE) -c -o $@ $^

$(BUILD_DIR)/btf.o: btf.c
	gcc -I$(INCLUDE) -c -o $@ $^

$(BUILD_DIR)/libbpf.o: libbpf.c
	gcc -I$(INCLUDE) -c -o $@ $^

$(BUILD_DIR)/gen.o: bpftool/gen.c
	gcc -I$(INCLUDE) -c -o $@ $^

$(BUILD_DIR)/bpftool: $(OBJS)
	gcc $^ -o $@ -lelf

clean:
	cd $(BUILD_DIR) && rm -rf ./*

build_dir:
	mkdir -p $(BUILD_DIR)

build: $(BUILD_DIR)/bpftool

all: clean build_dir build
