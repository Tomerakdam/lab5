#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <elf.h> //Elf_phder
/*ELf32_phdr is struct for Elf_file headers table 
i have p_type for the segment type for exanple PT_LOAD
i have p_offset for the placement of the segment in the file
...... p_vaddr for the virtual address that it should be loaded to
p_paddr physical address
p_filesz the size of the segment in the file
p_memsz size of the segment in the memory
p_flags flags like read write exec
p_align allignment

*/
//received the header table of an ELF file and index and printing a table of headers
void print_headers(Elf32_Phdr *phdr,int index){ 
    /*we are planning to print a table in the following form:
    Type offset virtaddr phyaddr filesiz memsiz flg align 
    */
    char *type_string; //type of the segment
    switch (phdr->p_type){
        case PT_NULL: type_string="NULL"; break;
        case PT_LOAD: type_string="LOAD"; break;
        case PT_DYNAMIC: type_string="DYNAMIC"; break;
        case PT_INTERP: type_string="INTERP"; break;
        case PT_NOTE: type_string="NOTE"; break;
        case PT_PHDR: type_string="PHDR"; break;
        default: type_string="UNKNOWN"; break;
    }
    //print header info in our format
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

    if (phdr->p_type==PT_LOAD){ // if it a load segment that should be mmapped
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
/*a function that recieve map_start which is the address in virtual memory
the executale is mapped to
function that will be applied on each Phdr
arg*/
int foreach_phdr(void *map_start, void (*func)(Elf32_Phdr *,int),int arg){
    //Elf32_ehdr is a truct that following this format
    /*
    e_type - the file type relocatable/executable
    e_machine - arichtecture type
    e_version -....
    e_entry - the entru address
    e_phoff - the offset to the program headers table
    e_phnum - the number of program headers
    e_phentsize the size of sepcific header
    ect....
    */
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *) map_start; //casting map_start to get the struct data
    if (ehdr->e_phoff==0 || ehdr->e_phnum==0){ //if there is offset or headers we have error
        perror("error in ELF\n");
        return -1;
    }
    for (int i=0;i<ehdr->e_phnum;i++){//runing other all headers
    //casting and moving to the correct header
        Elf32_Phdr *phdr= (Elf32_Phdr *)((char *)map_start+ehdr->e_phoff+i*ehdr->e_phentsize);
        func(phdr,i);//applying function on phdr which would be print_headers
        
    }
    return 0;
}
/*
  The `startup` function serves as a "bridge"
  that transfers control to the loaded ELF program (e.g., loadme),
  simulating a normal execution with command-line arguments.
 
 What it does:
 1. Saves the caller's stack frame and registers.
 2. Pushes argv[i] (excluding argv[0], which is the program name) to the stack in reverse order.
 3. Pushes argc to the stack.
 4. Calls the loaded program’s entry point.
 5. After the loaded program returns, restores the original state and returns the exit value.
 */
//letting the makefile know that startup is extern func
extern void startup(int argc, char **argv, void (*entry)());

//task2b loading the LOAD segments
void load_phdr(Elf32_Phdr *phdr, int fd) { //assignment signatures
    //do nothing if thats not a LOAD type of header
    if (phdr->p_type!=PT_LOAD){
        return;
    }
    //checks for flags to give mmap
    int prot =0;
    if (phdr->p_flags & PF_R) prot |=PROT_READ;
    if (phdr->p_flags & PF_W) prot |=PROT_WRITE;
    if (phdr->p_flags & PF_X) prot |=PROT_EXEC;
    size_t pagesize = 0x1000;
    Elf32_Off offset_aligned = phdr->p_offset & ~(pagesize - 1);
    Elf32_Addr vaddr_aligned = phdr->p_vaddr & ~(pagesize - 1);
    size_t padding = phdr->p_vaddr - vaddr_aligned;
    //void *mmap(void *addr, size_t length, int prot, int flags,int fd, off_t offset);
    //mapping to memory
    size_t map_size = phdr->p_memsz + padding;
    void *mapped = mmap((void *)vaddr_aligned,
                        map_size,
                        prot,
                        MAP_FIXED | MAP_PRIVATE,
                        fd,
                        offset_aligned);

    //in case mmap failed
    if (mapped==MAP_FAILED){
        perror ("mmaped fail");
        exit(1);
    }
    
}
void load_elf (const char* filename,int argc,char **argv){
    // open descriptor
    int fd=open(filename,O_RDONLY);
    if (fd<0){
        perror("couldnt open filename:(( \n");
        exit(1);
    }
    struct stat st;
    //checks if the read from the file succeed
    //take the file descriptor and extract important infor such
    /*
    st_size - size of file in bytes
    
    */
    if (fstat(fd,&st)<0){
        perror("fstat");
        close(fd);
        exit(1);
    }
    //void *mmap(void *addr, size_t length, int prot, int flags,int fd, off_t offset);
    void *map_start=mmap(NULL,st.st_size,PROT_READ,MAP_PRIVATE,fd,0);
    if (map_start==MAP_FAILED) {
        perror("map_failed");
        close (fd);
        exit(1);
    }
    Elf32_Ehdr* ehdr=(Elf32_Ehdr*)map_start;
    //checks magic numbers
    if(ehdr->e_ident[0]!=0x7f || ehdr->e_ident[1]!='E' || ehdr->e_ident[2]!='L'
    || ehdr->e_ident[3]!='F'){
        perror("not an ELF\n");
        munmap(map_start, st.st_size);
        close(fd);
        exit(1);
    }
    //loading the segments 
    for (int i=0;i<ehdr->e_phnum;i++){ //ehdr->e_phnum is an array of headers
        Elf32_Phdr *phdr = (Elf32_Phdr *)((char *)map_start + ehdr->e_phoff + i * sizeof(Elf32_Phdr));
        load_phdr(phdr,fd);
    }
    void (*entry_point)() = (void (*)())ehdr->e_entry;
    startup(argc,argv,entry_point);
    munmap(map_start,st.st_size);
    close(fd);
}
int main (int argc,char **argv){
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <ELF program> [args...]\n", argv[0]);
        return 1;
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
    load_elf(argv[1], argc - 1, &argv[1]);
    munmap(map_start,st.st_size);
    close(fd);
    return 0;
}