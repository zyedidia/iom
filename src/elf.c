#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <gelf.h>

#include "iom.h"

EXPORT struct IOM *
iom_load(char *image, size_t size)
{
    Elf *elf = elf_memory(image, size);
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
        .elf = elf,
    };
    return iom;

err:
    elf_end(elf);
    return NULL;
}

static bool
copyscn(Elf_Scn  *scn_out, Elf_Scn *scn_in)
{
    Elf_Data *data_in, *data_out;
    GElf_Shdr shdr_in, shdr_out;

    if (gelf_getshdr(scn_in, &shdr_in) != &shdr_in)
        return false;

    size_t n = 0;
    while (n < shdr_in.sh_size && (data_in = elf_getdata(scn_in, data_in)) != NULL) {
        if ((data_out = elf_newdata(scn_out)) == NULL)
            return false;
        *data_out = *data_in;
    }

    if (gelf_getshdr(scn_out, &shdr_out) != &shdr_out)
        return false;

    shdr_out = shdr_in;

    if (gelf_update_shdr (scn_out, &shdr_out) == 0)
        return false;

    return true;
}

static Elf_Scn *
offscn(Elf *elf, GElf_Off offset)
{
    if (!elf)
        return NULL;

    Elf_Scn *scn = NULL;
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        GElf_Shdr shdr;
        if (gelf_getshdr(scn, &shdr) == NULL)
            continue;
        if (shdr.sh_offset == offset)
            return scn;
    }

    return NULL;
}

EXPORT bool
iom_done(struct IOM *iom, int fdout)
{
    Elf_Scn *scn_in, *scn_out;
    GElf_Ehdr ehdr_in, ehdr_out;
    int scn_index = 0;
    if (gelf_getehdr(iom->elf, &ehdr_in) != &ehdr_in)
        goto elf_err0;

    Elf *elf_out = elf_begin(fdout, ELF_C_WRITE, NULL);
    if (!elf_out)
        goto elf_err;

    if (gelf_newehdr(elf_out, ehdr_in.e_ident[EI_CLASS]) == 0)
        goto elf_err;
    if (gelf_getehdr(elf_out, &ehdr_out) != &ehdr_out)
        goto elf_err;
    ehdr_out = ehdr_in;
    ehdr_out.e_ehsize = 0;
    ehdr_out.e_phentsize = 0;
    ehdr_out.e_phnum = 0;
    ehdr_out.e_shentsize = 0;
    ehdr_out.e_shnum = 0;
    if (gelf_update_ehdr (elf_out, &ehdr_out) == 0) {
        goto elf_err;
    }

    {
        GElf_Phdr phdr_in, phdr_out;
        int ph_ndx;

        if (ehdr_in.e_phnum && gelf_newphdr (elf_out, ehdr_in.e_phnum) == 0) 
            goto elf_err;

        for (ph_ndx = 0; ph_ndx < ehdr_in.e_phnum; ++ph_ndx) {
            if (gelf_getphdr(iom->elf, ph_ndx, &phdr_in) != &phdr_in)
                goto elf_err;

            if (gelf_getphdr(elf_out, ph_ndx, &phdr_out) != &phdr_out)
                goto elf_err;
            phdr_out = phdr_in;

            if (gelf_update_phdr(elf_out, ph_ndx, &phdr_out) == 0) 
                goto elf_err;
        }
    }
    for (scn_index = 1; scn_index < ehdr_in.e_shnum; scn_index++) {
        if ((scn_in = elf_getscn(iom->elf, scn_index)) == NULL) 
            goto elf_err;
        if ((scn_out = elf_newscn(elf_out)) == NULL)
            goto elf_err;
        if (copyscn(scn_out, scn_in) == 0) 
            goto elf_err;
    }
    {
        GElf_Phdr phdr_in, phdr_out;

        if (ehdr_in.e_phnum && gelf_newphdr (elf_out, ehdr_in.e_phnum) == 0) 
            goto elf_err;

        for (int ph_ndx = 0; ph_ndx < ehdr_in.e_phnum; ++ph_ndx) {
            GElf_Shdr shdr_out;
            if (gelf_getphdr (iom->elf, ph_ndx, &phdr_in) != &phdr_in)
                goto elf_err;

            if (gelf_getphdr(elf_out, ph_ndx, &phdr_out) != &phdr_out)
                goto elf_err;

            if (!phdr_in.p_offset || phdr_in.p_type == PT_PHDR)
                continue;
            if ((scn_in = offscn(iom->elf, phdr_in.p_offset)) == NULL) 
                goto elf_err;
            if ((scn_index = elf_ndxscn (scn_in)) == 0)
                goto elf_err;
            if ((scn_out = elf_getscn(elf_out, scn_index)) == NULL) 
                goto elf_err;
            if (gelf_getshdr(scn_out, &shdr_out) != &shdr_out)
                goto elf_err;

            phdr_out.p_offset = shdr_out.sh_offset;

            if (gelf_update_phdr (elf_out, ph_ndx, &phdr_out) == 0) 
                goto elf_err;
        }
    }
    if (elf_update(elf_out, ELF_C_WRITE) < 0)
        goto elf_err;
    elf_end(elf_out);
    return true;

elf_err:
    elf_end(elf_out);
elf_err0:
    iom_error = IOM_ERR_ELF;
    return false;
}
