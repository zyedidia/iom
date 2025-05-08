#pragma once

#include <stdbool.h>

#include <gelf.h>

#define EXPORT __attribute__((visibility("default")))

struct IOMInstr {
    uint8_t *bytes;
    size_t size;

    struct IOMSection *m_sec;
    struct IOMInstr *m_next;
    struct IOMInstr *m_prev;
};

struct IOMSection {
    struct IOM *m_iom;
    struct IOMInstr *m_root;
    size_t m_idx;
    Elf_Scn *m_relascn;
};

struct IOM {
    Elf *m_elf;
    int m_fd;
    Elf_Scn *m_symtab;

    struct IOMSection *sections;
    size_t nsections;
};

struct IOMSymbol {
    uint64_t addr;
    size_t size;
};

struct IOM *
iom_load(char *image, size_t size);

bool
iom_done(struct IOM *iom, int fdout);

struct IOMInstr *
iom_start(struct IOMSection *sec);

struct IOMInstr *
iom_next(struct IOMInstr *instr);

struct IOMInstr *
iom_prev(struct IOMInstr *instr);

void
iom_insert_before(struct IOMInstr *instr, struct IOMInstr ninstr);

void
iom_insert_after(struct IOMInstr *instr, struct IOMInstr ninstr);

struct IOMSymbol
iom_symbol(struct IOM *iom, const char *symbol);

extern _Thread_local int iom_error;

enum {
    IOM_ERR_NONE     = 0,
    IOM_ERR_ELF      = 1,
    IOM_ERR_ALLOC    = 2,
    IOM_ERR_STDIO    = 3,
    IOM_ERR_ELF_KIND = 4,
    IOM_ERR_ARCH     = 5,
    IOM_ERR_CS_OPEN  = 6,
};

// Returns the error code for the current error.
int
iom_errno(void);

// Returns a string description of the current error.
const char *
iom_errmsg(void);
