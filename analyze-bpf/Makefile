# analyze-bpftool
BUILD_DIR = ./build
INCLUDE := -Iinclude/ -Iinclude/uapi/
INCLUDE_BPFTOOL := -Ibpftool/include/
INCLUDE_LIBBPF := -Iinclude/ -Iinclude/uapi/

OBJS = $(BUILD_DIR)/main.o $(BUILD_DIR)/linker.o $(BUILD_DIR)/hashmap.o $(BUILD_DIR)/strset.o \
	$(BUILD_DIR)/btf.o $(BUILD_DIR)/libbpf.o $(BUILD_DIR)/gen.o $(BUILD_DIR)/usdt.o

OBJS_LIBTOOL = $(BUILD_DIR)/main.o $(BUILD_DIR)/gen.o

OBJS_LIBBPF = $(BUILD_DIR)/linker.o $(BUILD_DIR)/hashmap.o $(BUILD_DIR)/strset.o \
	$(BUILD_DIR)/btf.o $(BUILD_DIR)/libbpf.o $(BUILD_DIR)/usdt.o $(BUILD_DIR)/libbpf_probes.o \
	$(BUILD_DIR)/str_error.o

$(BUILD_DIR)/linker.o: linker.c
	gcc $(INCLUDE_LIBBPF) -c -o $@ $^

$(BUILD_DIR)/hashmap.o: hashmap.c
	gcc $(INCLUDE_LIBBPF) -c -o $@ $^

$(BUILD_DIR)/strset.o: strset.c
	gcc $(INCLUDE_LIBBPF) -c -o $@ $^

$(BUILD_DIR)/btf.o: btf.c
	gcc $(INCLUDE_LIBBPF) -c -o $@ $^

$(BUILD_DIR)/libbpf.o: libbpf.c
	gcc $(INCLUDE_LIBBPF) -c -o $@ $^

$(BUILD_DIR)/usdt.o: usdt.c
	gcc $(INCLUDE_LIBBPF) -c -o $@ $^

$(BUILD_DIR)/libbpf_probes.o: libbpf_probes.c
	gcc $(INCLUDE_LIBBPF) -c -o $@ $^

$(BUILD_DIR)/str_error.o: str_error.c
	gcc $(INCLUDE_LIBBPF) -c -o $@ $^

$(BUILD_DIR)/libbpf.a: $(OBJS_LIBBPF)
	ar crv $@ $^

$(BUILD_DIR)/main.o: bpftool/main.c
	gcc $(INCLUDE_BPFTOOL) -c -o $@ $^

$(BUILD_DIR)/gen.o: bpftool/gen.c
	gcc $(INCLUDE_BPFTOOL) -c -o $@ $^

$(BUILD_DIR)/bpftool: $(OBJS_LIBTOOL) $(BUILD_DIR)/libbpf.a
	gcc $(OBJS_LIBTOOL) -o $@ -L./build/ -lbpf -lelf -lz

clean:
	cd $(BUILD_DIR) && rm -rf ./*

build_dir:
	mkdir -p $(BUILD_DIR)

build: $(BUILD_DIR)/bpftool
build_libbpf: $(BUILD_DIR)/libbpf.a

all: clean build_dir build
libbpf: clean build_dir build_libbpf
