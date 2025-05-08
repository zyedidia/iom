#include <capstone/capstone.h>

#include "arm64.h"
#include "iom.h"

static bool
disinit(GElf_Ehdr *ehdr, csh *handle)
{
    switch (ehdr->e_machine) {
    case EM_AARCH64:
        if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, handle) != CS_ERR_OK) {
            iom_error = IOM_ERR_CS_OPEN;
            return false;
        }
        break;
    default:
        iom_error = IOM_ERR_ARCH;
        return false;
    }
    cs_option(*handle, CS_OPT_DETAIL, CS_OPT_ON);
    return true;
}

bool
disinstrs(struct IOMSection *sec, Elf_Scn *scn)
{
    GElf_Ehdr ehdr;
    if (gelf_getehdr(sec->m_iom->m_elf, &ehdr) == NULL) {
        iom_error = IOM_ERR_ELF;
        return false;
    }
    csh handle;
    if (!disinit(&ehdr, &handle))
        return false;

    return true;
}
