#pragma once

#include <stdbool.h>

#include <gelf.h>

#define EXPORT __attribute__((visibility("default")))

struct IOM {
    Elf *elf;
};

struct IOM *
iom_load(char *image, size_t size);

bool
iom_done(struct IOM *iom, int out_fd);

extern _Thread_local int iom_error;

enum {
    IOM_ERR_NONE     = 0,
    IOM_ERR_ELF      = 1,
    IOM_ERR_ALLOC    = 2,
    IOM_ERR_STDIO    = 3,
    IOM_ERR_ELF_KIND = 4,
};

// Returns the error code for the current error.
int
iom_errno(void);

// Returns a string description of the current error.
const char *
iom_errmsg(void);
