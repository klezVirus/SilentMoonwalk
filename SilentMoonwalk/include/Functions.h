#pragma once
#include "Windows.h"

#ifdef _DEBUG
#define DPRINTUNWINDCODE(x) { \
	printf("0x%x\t", x->CodeOffset);		\
	printf("0x%x\t", x->OpInfo);			\
	printf("0x%x\n", x->UnwindOp);			\
}

#else
#define DPRINTUNWINDCODE(x) {}
#endif
#ifdef _DEBUG
#ifdef _VERBOSE_DEBUG
#define DPRINTCTX(x) { \
	printf("RAX: 0x%llx -", x.Rax);			\
	printf("RBX :0x%llx -", x.Rbx);			\
	printf("RCX: 0x%llx -", x.Rcx);			\
	printf("RDX: 0x%llx -", x.Rdx);			\
	printf("RDI: 0x%llx -", x.Rdi);			\
	printf("RSI: 0x%llx -", x.Rsi);			\
	printf("RBP: 0x%llx -", x.Rbp);			\
	printf("RSP: 0x%llx -\n", x.Rsp);			\
	printf("R8 : 0x%llx -", x.R8 );			\
	printf("R9 : 0x%llx -", x.R9 );			\
	printf("R10: 0x%llx -", x.R10);			\
	printf("R11: 0x%llx -", x.R11);			\
	printf("R12: 0x%llx -", x.R12);			\
	printf("R13: 0x%llx -", x.R13);			\
	printf("R14: 0x%llx -", x.R14);			\
	printf("R15: 0x%llx \n", x.R15);			\
	printf("RIP: 0x%llx \n", x.Rip);			\
	}
#else
#define DPRINTCTX(x) {}
#endif
#else
#define DPRINTCTX(x) {}
#endif

typedef PIMAGE_RUNTIME_FUNCTION_ENTRY PERF;
typedef SIZE_T(WINAPI* VirtualQueryType)(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
typedef HANDLE(WINAPI* OpenProcessType)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
typedef DWORD(WINAPI* GetCurrentProcessIdType)();

PIMAGE_RUNTIME_FUNCTION_ENTRY RTFindFunctionByAddress(UINT64, DWORD64);
PIMAGE_RUNTIME_FUNCTION_ENTRY RTFindFunctionByIndex(UINT64, DWORD);
DWORD GetStackFrameSize(HMODULE, PVOID, DWORD*);
DWORD GetStackFrameSizeWhereRbpIsPushedOnStack(HMODULE, PVOID, DWORD*);
DWORD GetStackFrameSizeIgnoringUwopSetFpreg(HMODULE, PVOID, DWORD*);
void PrintUnwindInfo(HMODULE, PVOID);
void LookupSymbolFromRTIndex(HMODULE, int, bool);
void EnumAllRTFunctions(HMODULE);
DWORD FindRTFunctionsUnwind(HMODULE, PVOID);


VOID FindGadget(HMODULE moduleBase, PERF pRuntimeFunctionTable, DWORD rtLastIndex, PDWORD stackSize, PDWORD prtSaveIndex, PDWORD skip, DWORD gadgetType);
DWORD FindProlog(HMODULE moduleBase, PERF pRuntimeFunctionTable, DWORD rtLastIndex, PDWORD stackSize, PDWORD prtSaveIndex, PDWORD skip, PDWORD64 rtTargetOffset);
DWORD FindPushRbp(HMODULE moduleBase, PERF pRuntimeFunctionTable, DWORD rtLastIndex, PDWORD stackSize, PDWORD prtSaveIndex, PDWORD skip, PDWORD64 rtTargetOffset);