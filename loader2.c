#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

//Provided in startup.s - jumps to the loaded program
int startup(int argc, char **argv, int (*entry)(int, char **));

// Converts ELF segment flags to mmap protection flags
static int flags_to_prot(Elf32_Word p_flags)
{
    int prot_bits = 0;
    if (p_flags & PF_R) prot_bits |= PROT_READ;
    if (p_flags & PF_W) prot_bits |= PROT_WRITE;
    if (p_flags & PF_X) prot_bits |= PROT_EXEC;
    return prot_bits;
}

//Iterates over all program headers and calls the given callback for each
static int foreach_program_header(void *file_base,
                                  void (*cb)(Elf32_Phdr *, int),
                                  int cb_arg)
{
    Elf32_Ehdr *elf_header = (Elf32_Ehdr *)file_base;

    //Check that the file is a valid 32-bit ELF
    if (memcmp(elf_header->e_ident, ELFMAG, SELFMAG) ||
        elf_header->e_ident[EI_CLASS] != ELFCLASS32) {
        fprintf(stderr, "error: not a 32-bit ELF\n");
        return -1;
    }

    Elf32_Phdr *ph_table =
        (Elf32_Phdr *)((char *)file_base + elf_header->e_phoff);

    for (int idx = 0; idx < elf_header->e_phnum; ++idx) {
        printf("program header #%d @ %p\n", idx, (void *)&ph_table[idx]);
        cb(&ph_table[idx], cb_arg);
    }
    return 0;
}

//Prints information about a program header in a readable format
static void print_header(Elf32_Phdr *hdr, int unused_arg)
{
    (void)unused_arg; //required by callback signature

    //Figure out the type of the segment
    const char *type_label;
    if      (hdr->p_type == PT_LOAD   ) type_label = "LOAD ";
    else if (hdr->p_type == PT_PHDR   ) type_label = "PHDR ";
    else if (hdr->p_type == PT_INTERP ) type_label = "INTERP";
    else if (hdr->p_type == PT_NOTE   ) type_label = "NOTE ";
    else if (hdr->p_type == PT_DYNAMIC) type_label = "DYN  ";
    else                                type_label = "OTHER";

    //Print the main details of the header
    printf("%-6s off=%08x vaddr=%08x fsz=%06x msz=%06x  "
           "%c%c%c  align=%x\n",
           type_label,
           hdr->p_offset, hdr->p_vaddr,
           hdr->p_filesz, hdr->p_memsz,
           (hdr->p_flags & PF_R) ? 'R' : '-',
           (hdr->p_flags & PF_W) ? 'W' : '-',
           (hdr->p_flags & PF_X) ? 'X' : '-',
           hdr->p_align);

    //Show the protection flags as a string
    char prot_string[4] = "";
    int  len = 0;
    if (hdr->p_flags & PF_R) prot_string[len++] = 'R';
    if (hdr->p_flags & PF_W) prot_string[len++] = 'W';
    if (hdr->p_flags & PF_X) prot_string[len++] = 'X';
    prot_string[len] = 0;
    if (len == 0) strcpy(prot_string, "-");

    printf("    mmap → prot=%s | MAP_PRIVATE | MAP_FIXED\n", prot_string);
}

//Maps a PT_LOAD segment into memory using mmap
static void map_load_segment(Elf32_Phdr *hdr, int elf_fd)
{
    if (hdr->p_type != PT_LOAD) return;  // Only map loadable segments

    //Align the mapping to the page boundary
    void  *dest_page  = (void *)(hdr->p_vaddr & ~0xFFFu);
    off_t  file_page  = hdr->p_offset & ~0xFFFu;
    size_t page_pad   = hdr->p_vaddr & 0xFFFu;
    size_t total_len  = hdr->p_memsz + page_pad;

    void *mapped = mmap(dest_page, total_len,
                        flags_to_prot(hdr->p_flags),
                        MAP_PRIVATE | MAP_FIXED,
                        elf_fd, file_page);

    if (mapped == MAP_FAILED) {
        perror("mmap");
        exit(2);
    }

    //If the segment has a .bss section, zero out the extra memory
    if (hdr->p_memsz > hdr->p_filesz) {
        size_t bss_gap = hdr->p_memsz - hdr->p_filesz;
        memset((char *)mapped + page_pad + hdr->p_filesz, 0, bss_gap);
    }
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <elf> [args]\n", argv[0]);
        return 1;
    }

    const char *elf_path = argv[1];

    //Open the ELF file for reading
    int elf_fd = open(elf_path, O_RDONLY);
    if (elf_fd < 0) { perror("open"); return 1; }

    //Find the size of the file
    off_t elf_size = lseek(elf_fd, 0, SEEK_END);
    void *elf_mem = mmap(NULL, elf_size, PROT_READ,
                         MAP_PRIVATE, elf_fd, 0);
    if (elf_mem == MAP_FAILED) { perror("mmap"); return 1; }

    //Print all program headers
    foreach_program_header(elf_mem, print_header, 0);

    //Map all PT_LOAD segments into memory
    if (foreach_program_header(elf_mem, map_load_segment, elf_fd) != 0) {
        munmap(elf_mem, elf_size);
        close(elf_fd);
        return 1;
    }

    //Get the entry point and jump to the loaded program
    Elf32_Ehdr *elf_header = (Elf32_Ehdr *)elf_mem;
    startup(argc - 1, argv + 1, (void *)elf_header->e_entry);

    //Clean up the mapping
    munmap(elf_mem, elf_size);
    return 0;
}
