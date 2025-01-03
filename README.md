# iEmulator
Author: **snow**

_icicle-emu based emulator plugin for Binary Ninja._


Supports: x86/x86_64

[![iEmu demo](https://i.imgur.com/clACzcr.png)](https://i.imgur.com/llLSA7g.mp4)

## Description:

### Right-click Controls
- Update RIP: Sets the current context RIP to the address that was clicked
- Run From: Updates the RIP and runs the emulator from the address that was clicked
- Run Selection: Updates RIP (start) and target (end) and runs the emulator from the start address to the end address
- Setup Args: Creates a window to input arguments for clicked function. This will update registers and write values to the stack address from the currently set stack pointer.
![](https://i.imgur.com/ElUPm3Q.png)

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

## Architectures
If you would like an architecture to be added, please open an issue or a pull request.
This should be trivial but takes some manual labor to add desired registers and mappings inside of `state/mappings.py`
Not every architecture will have a stack pointer so you do not have to modify `get_stack_pointer_register` if its appropriate.

## License

This plugin is released under an [MIT license](./license).
