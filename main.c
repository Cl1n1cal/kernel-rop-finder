#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <libelf.h>
#include <gelf.h>
#include <errno.h>
#include <capstone/capstone.h>

#define PAGE_SIZE 0x1000


int main(int argc, char **argv)
{
    if (argc < 2 || 2 < argc) {
        puts("Usage: ./kernel-rop-finder vmlinux");
        exit(1);
    }

    if (50 < strlen(argv[1])) {
        puts("Your vmlinux name cannot be more than 50 characters");
        puts("Usage: ./kernel-rop-finder vmlinux");
        exit(1);
    }

    char fname[60] = "";
    char prefix[] = "./";
    strcat(fname, prefix);
    strncpy(fname+sizeof(prefix)-1, argv[1], 50);

    uint32_t fd = open(fname, O_RDONLY);


    if (elf_version(EV_CURRENT) == EV_NONE) {
        fprintf(stderr, "libelf initialization failed!\n");
        exit(1);
    }

    Elf *e = elf_begin(fd, ELF_C_READ, NULL);
    if (!e) {
        fprintf(stderr, "elf_begin failed: %s\n", elf_errmsg(-1));
        close(fd);
        exit(1);
    }

    size_t shstrndx;
    if (elf_getshdrstrndx(e, &shstrndx) != 0) {
        fprintf(stderr, "elf_getshdrstrndx failed: %s\n", elf_errmsg(-1));
        elf_end(e);
        close(fd);
        exit(1);
    }

    uint64_t text_offset = 0;
    uint64_t base_addr = 0xffffffff81000000; // kernel .text virtual base (update this!)

    Elf_Scn *scn = NULL;
    while ((scn = elf_nextscn(e, scn)) != NULL) {
        GElf_Shdr shdr;
        if (!gelf_getshdr(scn, &shdr)) {
            fprintf(stderr, "gelf_getshdr failed: %s\n", elf_errmsg(-1));
            continue;
        }

        const char *name = elf_strptr(e, shstrndx, shdr.sh_name);
        if (!name) continue;

        if (strcmp(name, ".text") == 0) {
            printf("[+] Found .text section\n");
            printf("    Offset: 0x%lx\n", (long)shdr.sh_offset);
            printf("    Size  : 0x%lx (%lu bytes)\n", (long)shdr.sh_size, (unsigned long)shdr.sh_size);
            text_offset = shdr.sh_offset;
        }

    }

    printf("text offset: %lx\n", text_offset);


    // Allocate memory for .text parsing

    void *mem = malloc(PAGE_SIZE);
    void *tracker = mem;
    if (!mem) {
        perror("malloc");
        exit(1);
    }

    if (lseek(fd, text_offset, SEEK_SET) == (off_t) -1) {
    perror("lseek");
    free(mem);
    exit(1);
    }

    read(fd, mem, 0x1000);
    csh handle;
    cs_insn *insn;
    size_t count;


    // Initialize Capstone - x86 64-bit mode
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        fprintf(stderr, "Failed to initialize Capstone\n");
        return -1;
    }

    size_t acc = 0;
    while (acc < PAGE_SIZE - 0x100) {
        count = cs_disasm(handle, tracker, 15*5, base_addr + acc, 5, &insn); // max instr. length is 15 bytes
        size_t j;
        for (j = 0; j < count; j++) {
            if (j == 0) {
                printf("0x%"PRIx64":\t%s %s ;", insn[j].address, insn[j].mnemonic, insn[j].op_str);
            } else {
                printf(" %s %s ;", insn[j].mnemonic, insn[j].op_str);
            }
        }
        puts("");

        tracker += insn->size; // increment the tracker the amount of bytes interpreted as instr.
        acc += insn->size; // increment the accumulator to track how far we are in the page

        cs_free(insn, count);
    }


    /*



    size_t acc = 0;
    int k = 0;
    while(k < PAGE_SIZE-0x100) {
        acc = 0;

        count = cs_disasm(handle, mem+k, (uint64_t)mem - k, base_addr + k, 5, &insn);

        for (int i = 0; i < count; i++) {
            acc += insn[i].size;
        }

        if (acc == 0) {
            acc += 1;
        }

        if (count > 0) {
            size_t j;
            for (j = 0; j < count; j++) {
                if (j == 0) {
                    printf("0x%"PRIx64":\t%s %s ;", insn[j].address, insn[j].mnemonic, insn[j].op_str);
                } else {
                    printf(" %s %s ;", insn[j].mnemonic, insn[j].op_str);
                }
            }
            puts("");
            cs_free(insn, count);
        } else {
            printf("Failed to disassemble given code!\n");
        }
        k += acc;
    }

    cs_close(&handle);

    free(mem);

    */

    return 0;
}