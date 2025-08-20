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

/**
 * Check backwards, how many instructions up until 'ret' are valid
 */
size_t check_instr(cs_insn *instructions, size_t start_index)
{
    size_t result = 0;

    for (int i = start_index; i >= 0; i--) {
        if ((strcmp(instructions[i].mnemonic, "jmp") == 0) || (strcmp(instructions[i].mnemonic, "call") == 0) || (strcmp(instructions[i].mnemonic, "int3") == 0)) {
            break;
        }
        result += 1;
    }
    return result;
}

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
    uint64_t text_size = 0;

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
            text_size = shdr.sh_size;
        }

    }

    // Move to start of .text
    lseek(fd, text_offset, SEEK_SET);

    // Alloc mem for .text
    uint8_t *mem = malloc(text_size+0x20);
    if (mem == NULL) {
        perror("Malloc failed");
        exit(1);
    }

    // 0 initialize mem
    memset(mem, 0x00, text_size);
    puts("");

    // Read mem to buffer
    size_t read_count = read(fd, mem, text_size);
    if (read_count != text_size) {
        perror("Could not read all of .text");
        exit(1);
    }

    // Allocate memory for all instructions 
    cs_insn *instructions = calloc(text_size, sizeof(cs_insn));

    csh csh_handle;
    cs_insn *insn = NULL;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &csh_handle) != CS_ERR_OK) {
        fprintf(stderr, "Failed to initialize Capstone\n");
        return 1;
    }


    size_t index = 0;
    size_t count = 0;
    size_t offset = 0;
    size_t base_addr = 0xffffffff81000000;
    while(offset < text_size) {
        count = cs_disasm(csh_handle, mem + offset, 0xf, base_addr + offset, 0x1, &insn);
        if (count == 0) {
            // Invalid instruction - this will occur more than once
            offset += 1;
            continue;
        }
        memcpy(&instructions[index], insn, sizeof(cs_insn));
        index += 1;
        offset += insn->size;
        cs_free(insn, count);
    }


    // Allocate memory for ret gadgets
    cs_insn *res = calloc(text_size, sizeof(cs_insn));
    cs_insn *storage = calloc(5, sizeof(cs_insn));
    size_t check = 0;
    size_t tmp = 0;
    size_t counter = 0;

    size_t res_index = 0;
    for(int k = 0; k <= index; k++) {
        memset(storage, 0x00, 5*sizeof(cs_insn));
        
        // Look for ret gadget
        if (strcmp(instructions[k].mnemonic, "ret") == 0) {

            // If k < 4 take from 0 to 4
            if (k < 4) {
                for (int j = 0; j <= k; j++) {
                    memcpy(&storage[j], &instructions[j], sizeof(cs_insn));
                }

                check = check_instr(storage, k);

                tmp = k - check;

                for (int i = tmp; i < k; i++) {
                    memcpy(&res[res_index], &storage[i], sizeof(cs_insn));
                    res_index += 1;
                }
            }

            // If 4 <= k go back 4 indexes and take them including the ret, if they are not: call, jmp, int3
            if (4 <= k) {
                tmp = k - 4;
                counter = 0;
                for (int j = tmp; j <= k; j++) {
                    memcpy(&storage[counter], &instructions[j], sizeof(cs_insn));
                    counter += 1;
                }

                check = check_instr(storage, 4);

                tmp = 5 - check;

                for (int i = tmp; i <= 4; i++) {
                    memcpy(&res[res_index], &storage[i], sizeof(cs_insn));
                    res_index += 1;
                }
            }
        }
    }


    for (int k = 0; k < res_index; k++) {
        if (0 < k) {
            if ((strcmp(res[k-1].mnemonic, "ret") == 0)) {
                puts("");
                printf("0x%"PRIx64":\t%s %s ;", res[k].address, res[k].mnemonic, res[k].op_str);
                continue;
            }

            if ((strcmp(res[k].mnemonic, "ret") == 0)) {
                printf(" %s %s", res[k].mnemonic, res[k].op_str);
                continue;
            }

            printf(" %s %s ;", res[k].mnemonic, res[k].op_str);
            continue;
        }

        printf("0x%"PRIx64":\t%s %s ;", res[k].address, res[k].mnemonic, res[k].op_str);
        }

    puts("");

    // Close cs and free memory
    cs_close(&csh_handle);
    free(mem);
    free(storage);
    free(res);

    return 0;
}