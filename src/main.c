#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <argtable3.h>
#include <gelf.h>

#include "iom.h"
#include "file.h"

int
main(int argc, char **argv)
{
    struct arg_lit *help = arg_lit0("h", "help", "Show help");
    struct arg_lit *verbose = arg_lit0("V",  "verbose", "Verbose output");
    struct arg_file *output = arg_filen("o", "output", "<file>", 1, 100, "Output file");
    struct arg_file *inputs = arg_filen(NULL, NULL, "<file>", 1, 100, "Input files");
    struct arg_end *end = arg_end(20);

    void *argtable[] = { help, verbose, output, inputs, end };

    if (arg_nullcheck(argtable) != 0) {
        fprintf(stderr, "Memory allocation error\n");
        return 1;
    }

    int nerrors = arg_parse(argc, argv, argtable);

    if (help->count > 0) {
        printf("Usage: %s", argv[0]);
        arg_print_syntax(stdout, argtable, "\n");
        arg_print_glossary(stdout, argtable, "  %-25s %s\n");
        return 0;
    }

    if (nerrors > 0) {
        arg_print_errors(stderr, end, argv[0]);
        return 1;
    }

    if (verbose->count > 0) {
        printf("Verbose mode enabled\n");
    }

    if (elf_version(EV_CURRENT) == EV_NONE) {
        fprintf(stderr, "ELF initialization failed: %s\n", elf_errmsg(elf_errno()));
        return 1;
    }

    for (int i = 0; i < inputs->count; i++) {
        size_t size;
        char *fdata = fileread(inputs->filename[i], &size);
        if (!fdata) {
            fprintf(stderr, "error reading %s: %s\n", inputs->filename[i], iom_errmsg());
            continue;
        }

        int fdout = open(output->filename[0], O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (fdout < 0) {
            fprintf(stderr, "error opening %s: %s\n", output->filename[0], strerror(errno));
            continue;
        }

        struct IOM *iom = iom_load(fdata, size);
        if (!iom) {
            fprintf(stderr, "error initializing IOM for %s: %s\n", inputs->filename[i], iom_errmsg());
            continue;
        }

        if (!iom_done(iom, fdout)) {
            fprintf(stderr, "error saving IOM to %s: %s\n", output->filename[0], iom_errmsg());
        }
        close(fdout);
    }

    arg_freetable(argtable, sizeof(argtable) / sizeof(argtable[0]));

    return 0;
}
