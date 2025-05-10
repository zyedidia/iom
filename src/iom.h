#pragma once

#include <stdbool.h>

#include <gelf.h>
#include <capstone/capstone.h>

#define EXPORT __attribute__((visibility("default")))

struct IOMInstr {
    uint8_t *bytes;
    size_t size;

    size_t m_offset;
    cs_insn *m_insn;
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

struct IOMLoc {
    struct IOMInstr *instr;
    size_t offset;
};

struct IOMSymbol {
    uint64_t addr;
    size_t size;

    struct IOMLoc m_start;
    struct IOMLoc m_end;
};

struct IOMRelocCode {
    struct IOMLoc loc;
};

struct IOMRelocValue {
    struct IOMInstr *instr; // should this be IOMLoc?
    struct IOMLoc symstart; // should this be IOMLoc?
    struct IOMLoc value;
};

struct IOMRelocNew {
    struct IOMInstr *instr; // should this be IOMLoc?
    unsigned short type;

    // Reloc has a symbol if name is non-null
    const char *name;
    struct IOMLoc value; // should this be IOMLoc?
    GElf_Half shndx;
    unsigned char info;
};

struct IOMRelocOther {
    bool _none;
};

enum IOMRelocKind {
    IOM_RELOC_OTHER,
    IOM_RELOC_CODE,
    IOM_RELOC_VALUE,
    IOM_RELOC_NEW,
};

struct IOMReloc {
    enum IOMRelocKind kind;
    union {
        struct IOMRelocCode code;
        struct IOMRelocValue value;
        struct IOMRelocOther other;
        struct IOMRelocNew new_;
    } r;
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
    IOM_ERR_NONE      = 0,
    IOM_ERR_ELF       = 1,
    IOM_ERR_ALLOC     = 2,
    IOM_ERR_STDIO     = 3,
    IOM_ERR_ELF_KIND  = 4,
    IOM_ERR_ARCH      = 5,
    IOM_ERR_CS_OPEN   = 6,
    IOM_ERR_DISAS     = 7,
    IOM_ERR_NO_SYMTAB = 8,
};

// Returns the error code for the current error.
int
iom_errno(void);

// Returns a string description of the current error.
const char *
iom_errmsg(void);
