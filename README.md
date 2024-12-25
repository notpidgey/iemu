# iEmulator
Author: **snow**

_icicle-emu x86 based emulator plugin for Binary Ninja._

## Description:

### Controls
- Initialize: Initializes the emulator which allows for memory allocation to occur. Can only be clicked when in an offline state
- Run: Runs the emulator from the current RIP register until the emulator encounters a crash or exits
- Step: From the current RIP, executes a single instruction.
- Checkpoint: Creates a checkpoint which saves the emulator state including the contents of memory allocations. This includes the mapped sections of the binary. Be careful when using this as it saves the current state to memory.
- Restore: Restores the emulator state to the last checkpoint. This will restore the memory allocations and the mapped sections of the binary.
- Reset: Resets the emulator into an offline state. This will zero all the registers are reset all memory allocations.

### Context Tab
Contains all the register state for the current virtual machine context.
Once the emulator is in a running state, registers cannot be modified.

### Memory Tab

##### Sections
Contains sections that will be loaded into memory and their respective addresses. Can only be unchecked while the emulator is offline.

##### Allocations
Memory that has been allocated by the emulator. Region can be deallocated by right clicking

### Stack
Memory for the stack can be allocated here, it is the same as using the allocator inside the memory tab. It will automatically be set to RW permissions and RSP will be updated to the RSP entry.

Clicking "View" will populate the stack view with memory "Number of Rows" below and above the target address. This means if you select 8 rows, it will create 16.

### Dump
Dump view of allocated memory inside the emulator. Can only be used once the VM is not offline

"Size" represents the byte size of each grid cell

"Bytes" is the amount of bytes that will be shown per row

"Dump" brings up a prompt which allows you to dump the memory to a file

"Write String" allows you to write a string to the memory with the support of escape codes

## License

This plugin is released under an [MIT license](./license).
