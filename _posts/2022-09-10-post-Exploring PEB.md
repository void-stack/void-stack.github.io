---
title: "Analysing the Process Environment Block"
classes: wide
tagline: "The common theme amongst all Windows malware and implants is that they abuse the facilities provided by the Windows platform to achieve their objectives. Knowledge of the rich set of Windows APIs, understanding their usage in various stages of an implant, and leveraging them to detect and bypass various defenses in the system is essential for red and blue teamers."

header:
  overlay_image: /assets/images/.jpg

categories:
  - Blog
tags:
  - PEB
  - TEB
  - Windows Internals

toc: true
toc_label: "Overview"
toc_icon: "cog"
---

`The Process Environment Block` is a critical structure in the Windows OS, most of its fields are not intended to be used by other than the operating system. It contains data structures that apply across a whole process and is stored in user-mode memory, which makes it accessible for the corresponding process. The structure contains valuable information about the running process, including:
-  whether the process is being debugged or not
-  which modules are loaded into memory
-  the command line used to invoke the process

## Installation of WinDbg (Microsoft Store)

Download and install WinDbg, then attach it to the running process as the example I will be using `notepad.exe`.

![WINDBG](/assets/images/windbg.png)

Navigate to your installation directory, and open `WinDbg.exe`.
On the File menu, choose  `1) Open Executable` or `2) Attach to process`.

`1)` In the Open Executable dialog box, navigate to the folder that contains `notepad.exe` (typically, C:\Windows\System32). For the File name, enter notepad.exe. Select Open.

`2)` In the second option just pick the running process in our case it's `notepad.exe`.

![ATTACH](/assets/images/attach.png)

![PREVIEW](/assets/images/windbg_preview.png)

You should end up with something like this, near the bottom of the WinDbg window, in the command line, enter these commands.

## Overview of PEB structure
First, based on MSDN documentation the [PEB structure](https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb)

```cpp
typedef struct _PEB {
  BYTE                          Reserved1[2];
  BYTE                          BeingDebugged;
  BYTE                          Reserved2[1];
  PVOID                         Reserved3[2];
  PPEB_LDR_DATA                 Ldr;
  PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
  PVOID                         Reserved4[3];
  PVOID                         AtlThunkSListPtr;
  PVOID                         Reserved5;
  ULONG                         Reserved6;
  PVOID                         Reserved7;
  ULONG                         Reserved8;
  ULONG                         AtlThunkSListPtr32;
  PVOID                         Reserved9[45];
  BYTE                          Reserved10[96];
  PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
  BYTE                          Reserved11[128];
  PVOID                         Reserved12[1];
  ULONG                         SessionId;
} PEB, *PPEB;
```

The `PEB` isn’t fully documented, so you must use `WinDbg` to see its full structure or use sites like [!NirSoft](https://www.nirsoft.net/kernel_struct/vista/PEB.html).

```cpp
typedef struct _PEB
{
     UCHAR InheritedAddressSpace;
     UCHAR ReadImageFileExecOptions;
     UCHAR BeingDebugged;
     UCHAR BitField;
     ULONG ImageUsesLargePages: 1;
     ULONG IsProtectedProcess: 1;
     ULONG IsLegacyProcess: 1;
     ULONG IsImageDynamicallyRelocated: 1;
     ULONG SpareBits: 4;
     PVOID Mutant;
     PVOID ImageBaseAddress;
     PPEB_LDR_DATA Ldr;
     PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
     PVOID SubSystemData;
     PVOID ProcessHeap;
     PRTL_CRITICAL_SECTION FastPebLock;
     PVOID AtlThunkSListPtr;
     PVOID IFEOKey;
     ULONG CrossProcessFlags;
     ULONG ProcessInJob: 1;
     ULONG ProcessInitializing: 1;
     ULONG ReservedBits0: 30;
     union
     {
          PVOID KernelCallbackTable;
          PVOID UserSharedInfoPtr;
     };
     ULONG SystemReserved[1];
     ULONG SpareUlong;
     PPEB_FREE_BLOCK FreeList;
     ULONG TlsExpansionCounter;
     PVOID TlsBitmap;
     ULONG TlsBitmapBits[2];
     PVOID ReadOnlySharedMemoryBase;
     PVOID HotpatchInformation;
     VOID * * ReadOnlyStaticServerData;
     PVOID AnsiCodePageData;
     PVOID OemCodePageData;
     PVOID UnicodeCaseTableData;
     ULONG NumberOfProcessors;
     ULONG NtGlobalFlag;
     LARGE_INTEGER CriticalSectionTimeout;
     ULONG HeapSegmentReserve;
     ULONG HeapSegmentCommit;
     ULONG HeapDeCommitTotalFreeThreshold;
     ULONG HeapDeCommitFreeBlockThreshold;
     ULONG NumberOfHeaps;
     ULONG MaximumNumberOfHeaps;
     VOID * * ProcessHeaps;
     PVOID GdiSharedHandleTable;
     PVOID ProcessStarterHelper;
     ULONG GdiDCAttributeList;
     PRTL_CRITICAL_SECTION LoaderLock;
     ULONG OSMajorVersion;
     ULONG OSMinorVersion;
     WORD OSBuildNumber;
     WORD OSCSDVersion;
     ULONG OSPlatformId;
     ULONG ImageSubsystem;
     ULONG ImageSubsystemMajorVersion;
     ULONG ImageSubsystemMinorVersion;
     ULONG ImageProcessAffinityMask;
     ULONG GdiHandleBuffer[34];
     PVOID PostProcessInitRoutine;
     PVOID TlsExpansionBitmap;
     ULONG TlsExpansionBitmapBits[32];
     ULONG SessionId;
     ULARGE_INTEGER AppCompatFlags;
     ULARGE_INTEGER AppCompatFlagsUser;
     PVOID pShimData;
     PVOID AppCompatInfo;
     UNICODE_STRING CSDVersion;
     _ACTIVATION_CONTEXT_DATA * ActivationContextData;
     _ASSEMBLY_STORAGE_MAP * ProcessAssemblyStorageMap;
     _ACTIVATION_CONTEXT_DATA * SystemDefaultActivationContextData;
     _ASSEMBLY_STORAGE_MAP * SystemAssemblyStorageMap;
     ULONG MinimumStackCommit;
     _FLS_CALLBACK_INFO * FlsCallback;
     LIST_ENTRY FlsListHead;
     PVOID FlsBitmap;
     ULONG FlsBitmapBits[4];
     ULONG FlsHighIndex;
     PVOID WerRegistrationData;
     PVOID WerShipAssertPtr;
} PEB, *PPEB;
```

## Usage and useful commands when exploring the PEB.
Dump _PEB structure: `dt ntdll!_PEB`.
“dt” stands for “Display Type” and can be used to display information about a specific data-type

![PEB](/assets/images/peb.png)

PEB address of the process: `r $peb`.

![PEB_Addr](/assets/images/peb_addr.png)

The _PEB structure can now be overlaid on the memory pointed to by the `$peb` to see what values the structure members are holding/pointing to: `dt ntdll!_PEB @$peb`.

![PEB_overview](/assets/images/PEB_overview.png)

### BeingDebugged
`+0x002 BeingDebugged    : 0x1 ''`

The most obvious flag to identify is whether a debugger is attached to the process or not. By reading the variable directly from memory instead of using usual suspects like `NtQueryInformationProcess` or `IsDebuggerPresent`, malware can prevent noisy WINAPI calls. This makes it harder to spot this technique.

### Ldr (Getting a list of loaded modules)
`+0x018 Ldr              : 0x00007ffd5ed1a4c0 _PEB_LDR_DATA`

Is one of the most important fields in the PEB. This is a pointer to a structure that contains information about the process’s loaded modules, and to the Head node of a doubly-linked list.
The linked list can help us find the addresses of structures that represent the loaded DLLs.

We can get `InMemoryOrderModuleList` by `dt _PEB_LDR_DATA 0x00007ffd5ed1a4c0`

![inmodule](/assets/images/inmemory1.png)

Or more fancy way `dt _peb @$peb Ldr->InMemoryOrderModuleList`

![inmodule](/assets/images/inmodule.png)

Go go over linked list we can use `!list -x "dt _LDR_DATA_TABLE_ENTRY FullDllName->Buffer" 0x00000257b19a4210` where `0x00000257b19a4210` is our `InMemoryOrderModuleList`.

![list](/assets/images/list.png)

### ImageBaseAddress
`+0x010 ImageBaseAddress : 0x00007ff7f45b0000 Void`

Is it actually the valid address of the executable image in process memory we can try to inspect it using our PEB dump
`db 0x00007ff7f45b0000 L100`

![PEB_overview](/assets/images/imagebase.png)

### ProcessParameters 
Is a pointer to `RTL_USER_PROCESS_PARAMETERS` structure. To inspect it we are going to find `ProcessParameters` address. 

`dt _peb @$peb ProcessParameters` 

![Params1](/assets/images/params_1.png)

Now we can dump it using `dt _RTL_USER_PROCESS_PARAMETERS 0x00000257b19a37b0`

![Params](/assets/images/params.png)

Or we can forget about all of the above and just use: `!peb`

![PEB!](/assets/images/peb!.png)

## How the Process Environment Block (PEB) is actually found.
On the user mode basis of a `32-bit window`, the `FS` register points to a structure called a `Thread Environment Block (TEB)` or `Thread Information Block (TIB)`. This structure stores information about the currently running thread. This is mainly used because information can be obtained without calling API functions. Note that the `FS` register points to the first address of the `TEB`, so you can add values by position to access the desired fields. In the `x64 environment`, the `GS` register is used instead of the `FS` register.

### TEB Structure for x86/x64
![teb!](/assets/images/teb.png)

The `PEB` can be found at `fs:[0x30]` in the `Thread Environment Block (TEB)`/`Thread Information Block (TIB)` for x86 processes as well as at `gs:[0x60]` for x64 processes.

### x64 ASM
```cpp
GetPEB proc
mov rax, qword ptr gs:[00000060h] // move PEB from TEB into rax (64 bit process  gs : [0x60]);
ret                               // return rax
GetPEB endp
```

### x86 ASM
```cpp
__declspec(naked) PEB* __stdcall get_peb() 
{
  __asm mov eax, dword ptr fs : [0x30] ; // move PEB from TEB into eax (32 bit process fs : [0x30])
  __asm ret;                             // return eax
}
```

You do not need to use `ASM` for this, you can use intrinsic functions like so:
`__readfsdword`/`__readgsqword` are compiler intrinsic functions that will generate more optimized code, there is no reason to use inline assembly. Inline assembly is not even supported by Microsoft's compilers for 64-bit targets.

```cpp
PEB *GetPeb() 
{
#ifdef _M_X64
  return reinterpret_cast<PEB*>(__readgsqword(0x60));
#elif _M_IX86
  return reinterpret_cast<PEB*>(__readfsdword(0x30));
#else
  #error "PEB Architecture Unsupported"
#endif  
}
```

### Support non-ARM systems

Structure defined inside `winnt.h`. It's the staring point for the algorithm. It includes self-referencing field - Self pointer, offset of which is used on `non-ARM systems` to read `Thread Environment Block` data.

```cpp
typedef struct _NT_TIB {
    struct _EXCEPTION_REGISTRATION_RECORD *ExceptionList;
    PVOID StackBase;
    PVOID StackLimit;
    PVOID SubSystemTib;
#if defined(_MSC_EXTENSIONS)
    union {
        PVOID FiberData;
        DWORD Version;
    };
#else
    PVOID FiberData;
#endif
    PVOID ArbitraryUserPointer;
    struct _NT_TIB *Self;
} NT_TIB;
typedef NT_TIB *PNT_TIB;
```

After the executable is loaded by the Windows PE loader and before the thread starts running, `TEB` is saved to `fs(x86)` or `gs(x64)` processor register. `ARM` systems use different technique which utilize coprocessors scheme (it's unclear whether the coprocessor is real hardware component or emulated). Self field of `NT_TIB` is the `TEB` pointer for the current thread.

Even not officially documented, this behavior is observed on/for all available Windows operating systems with NT kernel.

Acquiring pointer to the `TEB` is done using Microsoft specific compiler intrinsics:

```cpp
#include <winnt.h>
#include <winternl.h>

#if defined(_M_X64) // x64
    auto pTeb = reinterpret_cast<PTEB>(__readgsqword(reinterpret_cast<DWORD>(&static_cast<NT_TIB*>(nullptr)->Self)));
#elif defined(_M_ARM) // ARM
    auto pTeb = reinterpret_cast<PTEB>(_MoveFromCoprocessor(15, 0, 13, 0, 2)); // CP15_TPIDRURW
#else // x86
    auto pTeb = reinterpret_cast<PTEB>(__readfsdword(reinterpret_cast<DWORD>(&static_cast<NT_TIB*>(nullptr)->Self)));
#endif
```

Among others, one of the fields inside the `TEB` is pointer to the `PEB (Process Environment Block)`.

## Access TEB the Windows way
User-mode code can easily find its own process’s `PEB`, albeit only by using undocumented or semi-documented behavior. While a thread executes in user mode, its `fs` or `gs` register, for 32-bit and 64-bit code respectively, addresses the thread’s TEB. That structure’s `ProcessEnvironmentBlock` member holds the address of the current process’s `PEB`. In NTDLL version 5.1 and higher, this simple work is available more neatly as an exported function, named `RtlGetCurrentPeb`, but it too is undocumented. Its implementation is something very like

```cpp
PEB *RtlGetCurrentPeb(VOID)
{
    return NtCurrentTeb()->ProcessEnvironmentBlock;
}

// For its own low-level user-mode programming, Microsoft has long had a macro or inlined 
// routine, apparently named NtCurrentPeb, which reads directly from fs or gs, e.g.
PEB *NtCurrentPeb (VOID)
{
    return (PEB *) __readfsdword (FIELD_OFFSET (TEB, ProcessEnvironmentBlock));
}
```

To use `NtCurrentTeb()` without Windows header files declare the function prototype and link against `ntdll.dll`.

## What's next?
In second part we’ll put the described how to manually write functions like `IsDebuggerPresent` or `GetModuleHandle` to see how a program can parse the `PEB` to recover `Kernel32.dll` address, and then load any other library. Not a single import is needed!