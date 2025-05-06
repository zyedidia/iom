#include <stdio.h>
#include <stdlib.h>

#include "iom.h"

char *
fileread(const char *filename, size_t *o_size)
{
    FILE *f = fopen(filename, "rb");
    if (!f) {
        iom_error = IOM_ERR_STDIO;
        return NULL;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        iom_error = IOM_ERR_STDIO;
        goto err1;
    }

    long size = ftell(f);
    if (size < 0) {
        iom_error = IOM_ERR_STDIO;
        goto err1;
    }

    rewind(f);

    char *buffer = malloc(size);
    if (!buffer) {
        iom_error = IOM_ERR_ALLOC;
        goto err1;
    }

    if (fread(buffer, 1, size, f) != (size_t) size) {
        iom_error = IOM_ERR_STDIO;
        goto err2;
    }

    fclose(f);
    if (o_size)
        *o_size = size;
    return buffer;

err2:
    free(buffer);
err1:
    fclose(f);
    return NULL;
}
