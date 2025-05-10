#include <string.h>

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

    Elf_Data *data = elf_getdata(scn, NULL);
    if (data == NULL) {
        iom_error = IOM_ERR_ELF;
        goto err;
    }

    const uint8_t *buf = (const uint8_t *) data->d_buf;
    size_t size = data->d_size;

    size_t n = 0;
    while (n < size) {
        cs_insn *insn = NULL;
        size_t count = cs_disasm(handle, &buf[n], size - n, n, 0, &insn);
        if (count != 1) {
            iom_error = IOM_ERR_DISAS;
            // TODO: provide address of instruction in error message.
            goto err;
        }

        struct IOMInstr *instr = malloc(sizeof(struct IOMInstr));
        uint8_t *bytes = malloc(insn->size);
        memcpy(bytes, &buf[n], insn->size);

        *instr = (struct IOMInstr) {
            .m_insn = insn,
            .m_sec = sec,
            .m_offset = n,
            .bytes = bytes,
            .size = insn->size,
        };

        // insert into linked list

        n += insn->size;
    }

    return true;

err:
    cs_close(&handle);
    return false;
}
