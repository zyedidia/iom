#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <gelf.h>

#include "iom.h"

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
        .elf = elf,
        .fd = fdtmp,
    };

    return iom;

err:
    elf_end(elf);
    return NULL;
}


EXPORT bool
iom_done(struct IOM *iom, int fdout)
{
    elf_update(iom->elf, ELF_C_WRITE);

    lseek(iom->fd, 0, SEEK_SET);
    char buf[BUFSIZ];
    ssize_t n;
    while ((n = read(iom->fd, buf, BUFSIZ)) > 0) {
        if (write(fdout, buf, n) != n) {
            iom_error = IOM_ERR_STDIO;
            return false;
        }
    }
    elf_end(iom->elf);
    close(iom->fd);
    return true;
}
