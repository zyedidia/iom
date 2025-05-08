#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <gelf.h>

#include "iom.h"
#include "dis.h"

static bool
loadinstrs(struct IOM *iom);

EXPORT struct IOM *
iom_load(char *image, size_t size)
{
    char template[] = "/tmp/iom.temp.XXXXXX";
    int fdtmp = mkstemp(template);
    if (fdtmp < 0) {
        iom_error = IOM_ERR_STDIO;
        return NULL;
    }
    unlink(template);
    if (write(fdtmp, image, size) != (ssize_t) size) {
        iom_error = IOM_ERR_STDIO;
        return NULL;
    }
    Elf *elf = elf_begin(fdtmp, ELF_C_RDWR, NULL);
    if (!elf) {
        iom_error = IOM_ERR_ELF;
        return NULL;
    }
    if (elf_kind(elf) != ELF_K_ELF) {
        iom_error = IOM_ERR_ELF_KIND;
        goto err;
    }
    struct IOM *iom = calloc(sizeof(struct IOM), 1);
    if (!iom) {
        iom_error = IOM_ERR_ALLOC;
        goto err;
    }
    *iom = (struct IOM) {
        .m_elf = elf,
        .m_fd = fdtmp,
    };

    if (!loadinstrs(iom))
        goto err2;

    return iom;

err2:
    free(iom);
err:
    elf_end(elf);
    return NULL;
}


EXPORT bool
iom_done(struct IOM *iom, int fdout)
{
    elf_update(iom->m_elf, ELF_C_WRITE);
    elf_end(iom->m_elf);

    lseek(iom->m_fd, 0, SEEK_SET);
    char buf[BUFSIZ];
    ssize_t n;
    while ((n = read(iom->m_fd, buf, BUFSIZ)) > 0) {
        if (write(fdout, buf, n) != n) {
            iom_error = IOM_ERR_STDIO;
            return false;
        }
    }
    close(iom->m_fd);
    return true;
}

EXPORT struct IOMInstr *
iom_start(struct IOMSection *sec)
{
    return sec->m_root;
}

EXPORT struct IOMInstr *
iom_next(struct IOMInstr *instr)
{
    return instr->m_next;
}

EXPORT struct IOMInstr *
iom_prev(struct IOMInstr *instr)
{
    return instr->m_prev;
}

static bool
loadinstrs(struct IOM *iom)
{
    GElf_Ehdr ehdr;
    if (gelf_getehdr(iom->m_elf, &ehdr) == NULL) {
        iom_error = IOM_ERR_ELF;
        return false;
    }

    size_t shnum;
    if (elf_getshdrnum(iom->m_elf, &shnum) != 0) {
        iom_error = IOM_ERR_ELF;
        return false;
    }

    Elf_Scn **relascns = calloc(sizeof(Elf_Scn *), shnum);
    size_t nscn = 0;
    Elf_Scn *symtab;
    Elf_Scn *scn = NULL;
    while ((scn = elf_nextscn(iom->m_elf, scn)) != NULL) {
        GElf_Shdr shdr;
        if (gelf_getshdr(scn, &shdr) == NULL)
            continue;
        if (shdr.sh_type == SHT_PROGBITS && (shdr.sh_flags & SHF_EXECINSTR))
            nscn++;
        if (shdr.sh_type == SHT_RELA)
            relascns[shdr.sh_info] = scn;
        if (shdr.sh_type == SHT_SYMTAB)
            symtab = scn;
    }

    struct IOMSection *sections = malloc(sizeof(struct IOMSection) * nscn);

    nscn = 0;
    scn = NULL;
    while ((scn = elf_nextscn(iom->m_elf, scn)) != NULL) {
        GElf_Shdr shdr;
        if (gelf_getshdr(scn, &shdr) == NULL)
            continue;
        if (shdr.sh_type == SHT_PROGBITS && (shdr.sh_flags & SHF_EXECINSTR)) {
            size_t idx = elf_ndxscn(scn);
            sections[nscn] = (struct IOMSection) {
                .m_iom = iom,
                .m_idx = idx,
                .m_relascn = relascns[idx],
            };
            // disassemble instructions from the section
            if (!disinstrs(&sections[nscn], scn))
                goto err;
            nscn++;
        }
    }

    iom->sections = sections;
    iom->nsections = nscn;
    iom->m_symtab = symtab;

    free(relascns);

    return true;

err:
    free(relascns);
    return false;
}
