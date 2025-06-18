#include <stdio.h> //NULL and stdin
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>  // for fstat
#include <elf.h> //Elf32_Phdr
#include <fcntl.h> //O_RDONLY
#include <sys/mman.h> //mmap

void print_headers(Elf32_Phdr *phdr,int index){
    char *type_string;
    // translate p_type to a  string
    switch (phdr->p_type){
        case PT_NULL: type_string="NULL"; break;
        case PT_LOAD: type_string="LOAD"; break;
        case PT_DYNAMIC: type_string="DYNAMIC"; break;
        case PT_INTERP: type_string="INTERP"; break;
        case PT_NOTE: type_string="NOTE"; break;
        case PT_PHDR: type_string="PHDR"; break;
        default: type_string="UNKNOWN"; break;

    }
    //print header info
    printf("%-8s 0x%06x 0x%08x 0x%08x 0x%06x 0x%06x ",
       type_string,
       phdr->p_offset,
       phdr->p_vaddr,
       phdr->p_paddr,
       phdr->p_filesz,
       phdr->p_memsz);

    //print flag
    printf("%c%c%c ",
        (phdr->p_flags & PF_R) ? 'R' : ' ',
        (phdr->p_flags & PF_W) ? 'W' : ' ',
        (phdr->p_flags & PF_X) ? 'E' : ' ');
    //print align
    printf("0x%x\n", phdr->p_align);

    if (phdr->p_type==PT_LOAD){ // if it a load segment
    // gonna check flags that we will send the mmap
        int prot=0;
        if (phdr->p_flags & PF_R) prot |=PROT_READ;
        if (phdr->p_flags & PF_W) prot |=PROT_WRITE;
        if (phdr->p_flags & PF_X) prot |=PROT_EXEC;

        printf("  → PROT =");
        if (prot & PROT_READ)  printf(" READ");
        if (prot & PROT_WRITE) printf(" WRITE");
        if (prot & PROT_EXEC)  printf(" EXEC");

        printf(" | MAP = MAP_PRIVATE");
    }
    printf("\n");

}
int foreach_phdr(void *map_start, void (*func)(Elf32_Phdr *,int),int arg){
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *) map_start;
    if (ehdr->e_phoff==0 || ehdr->e_phnum==0){ //if there is offset or headers
        perror("error in ELF\n");
        return -1;
    }
    for (int i=0;i<ehdr->e_phnum;i++){
        Elf32_Phdr *phdr= (Elf32_Phdr *)((char *)map_start+ehdr->e_phoff+i*ehdr->e_phentsize);
        func(phdr,i);
        
    }
    return 0;
}
int main (int argc, char **argv){
    if (argc != 2) {
    fprintf(stderr, "wrong amount of arguments\n");
    exit(1);
    }

    char *filename=argv[1];
    //open file for reead
    int fd=open(filename,O_RDONLY);
    if (fd<0){
        perror("cant open\n");
        exit(1);
    }
    struct stat st;
    if (fstat(fd,&st)<0){ //system call that checks for information details on a OPENED FILE
        //if the returned value is smaller than 0 there is an error
        perror ("errore in fstat\n");
        close(fd);
        exit(1); 
    }
    //void *mmap(void *addr, size_t length, int prot, int flags,int fd, off_t offset);
    void *map_start=mmap(NULL,st.st_size,PROT_READ,MAP_PRIVATE,fd,0);
    if (map_start==MAP_FAILED){
        perror("error mmap\n");
        close(fd);
        exit(1);
    }
    Elf32_Ehdr *edhr=(Elf32_Ehdr *)map_start;
    //we will check the magic number
    if (edhr->e_ident[0]==0x7f && edhr->e_ident[1]=='E' && edhr->e_ident[2]=='L'
    && edhr->e_ident[3]=='F'){
        printf("recieved ELF file\n");
    }
    else{
        perror("error ELF file\n");
        munmap(map_start,st.st_size);
        close(fd);
        exit(1);
    }
    printf("Type     Offset   VirtAddr   PhysAddr   FileSiz MemSiz   Flg  Align  [mmap flags]\n");//print first line
    foreach_phdr(map_start,print_headers,0);
    munmap(map_start,st.st_size);
    close(fd);
    return 0;
}