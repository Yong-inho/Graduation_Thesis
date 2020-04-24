## Executable and Linkable Format (ELF)

### Relocotable Object File

<img src="https://user-images.githubusercontent.com/62104730/80202863-38232b00-8661-11ea-8480-2591fbcd7af2.jpg" width="50%" height="50%" title="Relocatable Object File Format" alt="RubberDuck"></img>

* ELF header
Begins with a 16-byte sequence that describes...
  + word size
  + byte ordering of the system
  + the file offset of the section header table
  + the size and the number of entries in the section header table
  + etc...
  
* Section header table
Contains a fixed-size entry for each section in the object file

* Sections
  + .text   
    The machine code of the compiled program.
  + .rodata   
    Read-only data such as the format strings in printf statements, and jump tables for switch
  + .data   
    Initialized global and static C variables.
  + .bss
    Uninitialized global and static variables, along with any global or static variables that are   
    initialized to zero. -> This section occupies no actual space in the object file(placeholder)
  + .symtab
    A symbol table with information about functions and global variables. 
  + .rel.text
    A list of locations in the .text section that will be need to be modified when the linker   
    combines this object file with others
  + .rel.data
  + .debug & .line
    It is only present if the compiler driver is invoked with the -g options
  + .strtab
    A string table for the symbol tables in the .symtab and .debug sections and for the sectioin names    
    in the section headers -> sequence of null-terminated character strings.
    
### Executable Object File

