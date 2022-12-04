#include "Common.h"

#define JMP_RBX		 9215		// 0xff 0x23 --> reversed 0x23 0xff --> to Integer 9215
#define ADD_RSP_0x38 952402760  // 4883C438 --> reversed 38C48348 --> to Integer 952402760
#define RET			 0xc3		// One byte, no conversion needed

typedef struct
{

	/* POINTERS */
	PVOID KernelBaseAddress;
	PVOID KernelBaseAddressEnd;

	PVOID RtlUserThreadStartAddress;
	PVOID BaseThreadInitThunkAddress;

	PVOID  FirstFrameFunctionPointer;
	PVOID  SecondFrameFunctionPointer;
	PVOID  JmpRbxGadget;
	PVOID  AddRspXGadget;

	/* SIZES / OFFSETS */
	UINT64 FirstFrameSize;
	UINT64 FirstFrameRandomOffset;
	UINT64 SecondFrameSize;
	UINT64 SecondFrameRandomOffset;

	UINT64 JmpRbxGadgetFrameSize;
	UINT64 AddRspXGadgetFrameSize;

	UINT64 RtlUserThreadStartFrameSize;
	UINT64 BaseThreadInitThunkFrameSize;

	/* FRAME OFFSET */
	UINT64 StackOffsetWhereRbpIsPushed;

	/* OTHERS */
	PVOID  JmpRbxGadgetRef;
	PVOID  SpoofFunctionPointer;
	PVOID  ReturnAddress;

	/* SPOOFED FOUNCTION NUMBER OF PARAMETERS */
	UINT64 Nargs;
	/* SPOOFED FOUNCTION PARAMETERS */
	PVOID Arg01;
	PVOID Arg02;
	PVOID Arg03;
	PVOID Arg04;
	PVOID Arg05;
	PVOID Arg06;
	PVOID Arg07;
	PVOID Arg08;

} SPOOFER, * PSPOOFER;

VOID SpoofCallStack(PSPOOFER);
EXTERN_C PVOID spoof_call(PSPOOFER sConfig);
EXTERN_C PVOID spoof_call_synthetic(PSPOOFER sConfig);
EXTERN_C PVOID get_current_rsp();
