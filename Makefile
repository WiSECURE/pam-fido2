SRC_DIR := src
OBJ_DIR := build
TARGET := build/pam_fido2.so

CC := gcc
CFLAGS := -Wall -fPIC -DPIC
LDFLAGS := -shared -rdynamic
LIBS := -lpam -lcbor -lcrypto -ludev -lfido2
DEPS := $(wildcard $(SRC_DIR)/*.h)
SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))

all: ${TARGET}

${OBJ_DIR}:
	mkdir -p $@

${OBJ_DIR}/%.o: ${SRC_DIR}/%.c ${DEPS} | ${OBJ_DIR}
	${CC} ${CFLAGS} -c $< -o $@

${TARGET}: ${OBJS}
	${CC} ${LDFLAGS} ${OBJS} ${LIBS} -o ${TARGET}

.PHONY: clean test

clean:
	rm ${TARGET} ${OBJS}

test:
	python3 example/app-authentication/app.py
