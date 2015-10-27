#
#     Filename: Makefile
#  Description: Standalone makefile for packet classification platform
#
#       Author: Xiang Wang (xiang.wang.s@gmail.com)
#
# Organization: Network Security Laboratory (NSLab),
#               Research Institute of Information Technology (RIIT),
#               Tsinghua University (THU)
#

INC_DIR = inc
SRC_DIR = src
BIN_DIR = bin

rwildcard = $(foreach d, $(wildcard $1*), $(call rwildcard, $d/, $2) \
    $(filter $(subst *, %, $2), $d))

SRC = $(call rwildcard, $(SRC_DIR)/, *.c)
DEP = $(patsubst $(SRC_DIR)/%.c, $(BIN_DIR)/%.d, $(SRC))
OBJ = $(patsubst $(SRC_DIR)/%.c, $(BIN_DIR)/%.o, $(SRC))
BIN = $(BIN_DIR)/pc_plat

CC = gcc
# CFLAGS = -Wall -g -I$(INC_DIR)/
CFLAGS = -Wall -O2 -DNDEBUG -I$(INC_DIR)/

all: $(BIN)

ifneq "$(MAKECMDGOALS)" "clean"
    -include $(DEP)
endif

$(SRC_DIR)/%.s: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -S -o $@ $<

$(BIN_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(BIN_DIR)/%.d: $(SRC_DIR)/%.c
	@set -e; rm -f $@; [ ! -e $(dir $@) ] & mkdir -p $(dir $@); \
	$(CC) -M -MT $(patsubst %.d, %.o, $@) $(CFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$;

$(BIN): $(OBJ)
	$(CC) -o $@ $^ -lrt

clean:
	rm -rf $(BIN_DIR);

