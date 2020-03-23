## Import Handler

A collection of helper functions to extend the funcionality of GetModuleHandle and GetProcAddress to work with other processes.
All functions work for x86 and x64. When using a x64 process and the target process is running under wow64 make sure to used the _WOW64 variants of the functions.

---

### GetModuleHandle

- GetModuleHandleEx
  - GetModuleHandleExA
  - GetModuleHandleExW

- GetProcAddressEx_WOW64
  - GetProcAddressExA_WOW64
  - GetProcAddressExW_WOW64

These functions use the Tool Help Library (TlHelp32.h) to enumerate the modules in the target process and return the base address of the specified module.
The process handle needs the PROCESS_QUERY_INFORMATION or PROCESS_QUERY_LIMITED_INFORMATION access right.

The _WOW64 variants ignore the x64 modules of a wow64 process.

---

### GetProcAddress

- GetProcAddressEx
- GetProcAddressEx_WOW64

These functions use ReadProcessMemory to walk through the specified module's export directory. In addition to the above mentioned access right this handles needs PROCESS_VM_READ access aswell.
The function name can be a function ordinal. Forwarded functions are handled recursively. API sets are not handled.
