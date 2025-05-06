#include <assert.h>
#include <errno.h>
#include <string.h>

#include <gelf.h>

#include "iom.h"

_Thread_local int iom_error;

EXPORT int
iom_errno(void)
{
    return iom_error;
}

EXPORT const char *
iom_errmsg(void)
{
    switch (iom_error) {
    case IOM_ERR_NONE:
        return "no error";
    case IOM_ERR_ELF:
        return elf_errmsg(elf_errno());
    case IOM_ERR_ALLOC:
        return "allocation failure";
    case IOM_ERR_STDIO:
        return strerror(errno);
    case IOM_ERR_ELF_KIND:
        return "not an ELF file";
    }
    return "unknown error";
}
