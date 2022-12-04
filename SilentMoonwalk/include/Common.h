#pragma once

#ifndef COMMON_H_INCLUDED
#define COMMON_H_INCLUDED

#include <Windows.h>
#include <psapi.h>
#include <dbghelp.h>
#include "AddressHunter.h"

#define SEED 123456
#define MAX_FRAMES 154
// Remove if you have a self-made definition of memcmp
#define MemCompare memcmp
// Using custom printf
#define printf custom_printf
void custom_printf(const char* pszFormat, ...);

// Removing malloc deps
#undef  malloc
#define malloc(x)   HeapAlloc(GetProcessHeap(), 0, x)

#undef  realloc
#define realloc(x,s) HeapReAlloc(GetProcessHeap(), 0, x, s)

#undef  free
#define free(x)     HeapFree(GetProcessHeap(), 0, x)

// Removing memset deps
void* custom_memset(void* dest, int c, size_t count);

#ifdef _DEBUG
#define DPRINT(...) { printf(__VA_ARGS__); }
#else
#define DPRINT(...) {}
#endif
#define HIDWORD(l) ((DWORD)(((DWORDLONG)(l)>>32)&0xFFFFFFFF))

#define BitVal(data,y) ( (data>>y) & 1) 

#define BitChainInfo(data) BitVal(data, 2) 
#define BitUHandler(data) BitVal(data, 1) 
#define BitEHandler(data) BitVal(data, 0) 
#define Version(data) BitVal(data, 4)*2 + BitVal(data, 3) 

#define BYTE_TO_BINARY_PATTERN "%c%c%c%c%c%c%c%c"
#define B2BP BYTE_TO_BINARY_PATTERN
#define BYTE_TO_BINARY(byte)  \
  (byte & 0x80 ? '1' : '0'), \
  (byte & 0x40 ? '1' : '0'), \
  (byte & 0x20 ? '1' : '0'), \
  (byte & 0x10 ? '1' : '0'), \
  (byte & 0x08 ? '1' : '0'), \
  (byte & 0x04 ? '1' : '0'), \
  (byte & 0x02 ? '1' : '0'), \
  (byte & 0x01 ? '1' : '0') 


typedef UCHAR UBYTE;

typedef enum _REGISTERS {
    RAX = 0,
    RCX,
    RDX,
    RBX,
    RSP,
    RBP,
    RSI,
    RDI,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15
} REGISTERS;


typedef union _UNWIND_CODE {
    struct {
        UBYTE CodeOffset;  // 0xFF00
        UBYTE UnwindOp : 4; // 0x000f OPCODE
        UBYTE OpInfo : 4;   // 0x00f0 
    };
    USHORT FrameOffset;
} UNWIND_CODE, * PUNWIND_CODE;

typedef struct _UNWIND_INFO {
    UBYTE Version : 3;
    UBYTE Flags : 5;    // 4 bytes
    UBYTE SizeOfProlog; // 4 bytes
    UBYTE CountOfCodes; // 4 bytes
    UBYTE FrameRegister : 4; 
    UBYTE FrameOffset : 4; // 4bytes
    UNWIND_CODE UnwindCode[1];
    union {
        OPTIONAL ULONG ExceptionHandler;
        OPTIONAL ULONG FunctionEntry;
    };
    OPTIONAL ULONG ExceptionData[]; 
} UNWIND_INFO, * PUNWIND_INFO;

#define GetUnwindCodeEntry(info, index) \
    ((info)->UnwindCode[index])

#define GetLanguageSpecificDataPtr(info) \
    ((PVOID)&GetUnwindCodeEntry((info),((info)->CountOfCodes + 1) & ~1))

#define GetExceptionHandler(base, info) \
    ((PEXCEPTION_ROUTINE)((base) + *(PULONG)GetLanguageSpecificDataPtr(info)))

#define GetChainedFunctionEntry(base, info) \
    ((PRUNTIME_FUNCTION)((base) + *(PULONG)GetLanguageSpecificDataPtr(info)))

#define GetExceptionDataPtr(info) \
    ((PVOID)((PULONG)GetLanguageSpecificDataPtr(info) + 1))

#if !defined(_IMAGEHLP_SOURCE_) && defined(_IMAGEHLP64)
#define ADDRESS ADDRESS64
#define LPADDRESS LPADDRESS64
#else
typedef struct _tagADDRESS {
    DWORD         Offset;
    WORD          Segment;
    ADDRESS_MODE  Mode;
} ADDRESS, * LPADDRESS;
#endif

typedef struct _MIN_CTX {

    DWORD64 Rax;
    DWORD64 Rcx;
    DWORD64 Rdx;
    DWORD64 Rbx;
    DWORD64 Rsp;
    DWORD64 Rbp;
    DWORD64 Rsi;
    DWORD64 Rdi;
    DWORD64 R8;
    DWORD64 R9;
    DWORD64 R10;
    DWORD64 R11;
    DWORD64 R12;
    DWORD64 R13;
    DWORD64 R14;
    DWORD64 R15;

    DWORD64 Rip;
    DWORD64 Reserved;
    DWORD64 StackSize;

} MIN_CTX, *PMIN_CTX;

typedef enum _UNWIND_OP_CODES {
    // x86_64. https://docs.microsoft.com/en-us/cpp/build/exception-handling-x64.
    UWOP_PUSH_NONVOL = 0,
    UWOP_ALLOC_LARGE,       // 1
    UWOP_ALLOC_SMALL,       // 2
    UWOP_SET_FPREG,         // 3
    UWOP_SAVE_NONVOL,       // 4
    UWOP_SAVE_NONVOL_BIG,   // 5
    UWOP_EPILOG,            // 6
    UWOP_SPARE_CODE,        // 7
    UWOP_SAVE_XMM128,       // 8
    UWOP_SAVE_XMM128BIG,    // 9
    UWOP_PUSH_MACH_FRAME,   // 10

    // ARM64. https://docs.microsoft.com/en-us/cpp/build/arm64-exception-handling
    UWOP_ALLOC_MEDIUM,
    UWOP_SAVE_R19R20X,
    UWOP_SAVE_FPLRX,
    UWOP_SAVE_FPLR,
    UWOP_SAVE_REG,
    UWOP_SAVE_REGX,
    UWOP_SAVE_REGP,
    UWOP_SAVE_REGPX,
    UWOP_SAVE_LRPAIR,
    UWOP_SAVE_FREG,
    UWOP_SAVE_FREGX,
    UWOP_SAVE_FREGP,
    UWOP_SAVE_FREGPX,
    UWOP_SET_FP,
    UWOP_ADD_FP,
    UWOP_NOP,
    UWOP_END,
    UWOP_SAVE_NEXT,
    UWOP_TRAP_FRAME,
    UWOP_CONTEXT,
    UWOP_CLEAR_UNWOUND_TO_CALL,
    // ARM: https://docs.microsoft.com/en-us/cpp/build/arm-exception-handling

    UWOP_ALLOC_HUGE,
    UWOP_WIDE_ALLOC_MEDIUM,
    UWOP_WIDE_ALLOC_LARGE,
    UWOP_WIDE_ALLOC_HUGE,

    UWOP_WIDE_SAVE_REG_MASK,
    UWOP_WIDE_SAVE_SP,
    UWOP_SAVE_REGS_R4R7LR,
    UWOP_WIDE_SAVE_REGS_R4R11LR,
    UWOP_SAVE_FREG_D8D15,
    UWOP_SAVE_REG_MASK,
    UWOP_SAVE_LR,
    UWOP_SAVE_FREG_D0D15,
    UWOP_SAVE_FREG_D16D31,
    UWOP_WIDE_NOP, // UWOP_NOP
    UWOP_END_NOP,  // UWOP_END
    UWOP_WIDE_END_NOP,
    // Custom implementation opcodes (implementation specific).
    UWOP_CUSTOM,
} UNWIND_OP_CODES;

// Stack allocations use UOP_AllocSmall, UOP_AllocLarge from above, plus
// the following. AllocSmall, AllocLarge and AllocHuge represent a 16 bit
// instruction, while the WideAlloc* opcodes represent a 32 bit instruction.
// Small can represent a stack offset of 0x7f*4 (252) bytes, Medium can
// represent up to 0x3ff*4 (4092) bytes, Large up to 0xffff*4 (262140) bytes,
// and Huge up to 0xffffff*4 (67108860) bytes.


#if !defined(_IMAGEHLP_SOURCE_) && defined(_IMAGEHLP64)
#define STACKFRAME STACKFRAME64
#define LPSTACKFRAME LPSTACKFRAME64
#else
typedef struct _tagSTACKFRAME {
    ADDRESS     AddrPC;
    ADDRESS     AddrReturn;
    ADDRESS     AddrFrame;
    ADDRESS     AddrStack;
    PVOID       FuncTableEntry;
    DWORD       Params[4];
    BOOL        Far;
    BOOL        Virtual;
    DWORD       Reserved[3];
    KDHELP      KdHelp;
    ADDRESS     AddrBStore;
} STACKFRAME, * LPSTACKFRAME;
#endif


BYTE ExtractOpInfo(BYTE OpIC) {
    return OpIC >> 4;
}

BYTE ExtractOpCode(BYTE OpIC) {
    return OpIC & 0x0F;
}

char* GetOpInfo(int op) {
    char* reg = (char*)malloc(4);
    if (reg == NULL) {
        return NULL;
    }
    
    custom_memset(reg, 0, 4);

    if(op == 0) {
        memcpy(reg, "RAX", 4);
    }
    else if(op == 1) {
        memcpy(reg, "RCX", 4);
    }
    else if(op == 2) {
        memcpy(reg, "RDX", 4);
    }
    else if(op == 3) {
        memcpy(reg, "RBX", 4);
    }
    else if(op == 4) {
        memcpy(reg, "RSP", 4);
    }
    else if(op == 5) {
        memcpy(reg, "RBP", 4);
    }
    else if(op == 6) {
        memcpy(reg, "RSI", 4);
    }
    else if(op == 7) {
        memcpy(reg, "RDI", 4);
    }
    else if(op == 8) {
        memcpy(reg, "R8\0", 4);
    }
    else if(op == 9) {
        memcpy(reg, "R9\0", 4);
    }
    else if(op == 10) {
        memcpy(reg, "R10", 4);
    }
    else if(op == 11) {
        memcpy(reg, "R11", 4);
    }
    else if(op == 12) {
        memcpy(reg, "R12", 4);
    }
    else if(op == 13) {
        memcpy(reg, "R13", 4);
    }
    else if(op == 14) {
        memcpy(reg, "R14", 4);
    }
    else if(op == 15) {
        memcpy(reg, "R15", 4);
    }
    return reg;
}

void custom_printf(const char* pszFormat, ...) {
    char buf[1024];
    va_list argList;
    va_start(argList, pszFormat);
    wvsprintfA(buf, pszFormat, argList);
    va_end(argList);
    DWORD done;
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), buf, strlen(buf), &done, NULL);
}

void* custom_memset(void* dest, int val, size_t len) {
    for (char* dst = (char*)dest; len != 0; len--) {
        *dst++ = val;
    }
    return dest;
}

static unsigned long int next = 1;

int rand(void) // RAND_MAX assumed as 256 + 20
{
    next = next * 1103515245 + 12345;
    return ((unsigned int)(next / 65536) % 0x7f) + 0x20;
}

void srand(unsigned int seed)
{
    next = seed;
}

#endif