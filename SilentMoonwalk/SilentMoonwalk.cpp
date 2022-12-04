#pragma once
#include "include/Common.h"
#include "include/Functions.h"
#include "include/Spoof.h"
#include <intrin.h>

// Define the target function
// 0: getchar
// 1: MessageBox
// 2: ShellExecuteA

#define TARGET 1

// Define the call stack
// 0: We use JOP gadget to desync the stack
// 1: We use two artificial frames to emulate thread stack initialization

#define CALL_STACK_TYPE 0

#if (CALL_STACK_TYPE == 1)
#define SPOOF_CALL spoof_call_synthetic
#else
#define SPOOF_CALL spoof_call
#endif

#pragma intrinsic(_ReturnAddress)
#pragma comment(linker, "/ENTRY:main")

SPOOFER sConfig;
PVOID returnAddress;

// Entry Point
void main() {
    PERF                pRuntimeFunctionTable;
    PERF                rtFunction;
    DWORD               runtimeFunctionTableSize;
    DWORD               rtLastIndex;
    DWORD               rtSaveIndex;
    DWORD               stackSize;
    DWORD               stackOffsetWhereRbpIsPushed;
    DWORD64             rtTargetOffset;
    HMODULE             kernel32Base;
    HMODULE             kernelBase;
    HMODULE             ntdllBase;
    PUNWIND_INFO        unwindInfo;
    BOOL                status;
    BOOL                checkpoint;
    HMODULE             msvcrt;
    HMODULE             user32;
    HMODULE             shell32;
    DWORD               addRspGadget;
    DWORD               skip_jmp_gadget          = 0;
    DWORD               skip_stack_pivot_gadget  = 0;
    DWORD               skip_prolog_frame        = 0;
    DWORD               skip_pop_rsp_frame       = 0;

    ntdllBase               = (HMODULE)GetModule(NTDLL_HASH);
    kernelBase              = (HMODULE)GetModule(KERNELBASE_HASH);
    kernel32Base            = (HMODULE)GetModule(KERNEL32DLL_HASH);
    pRuntimeFunctionTable   = (PERF)(GetExceptionDirectoryAddress(kernelBase, &runtimeFunctionTableSize));
    rtLastIndex             = (DWORD)(runtimeFunctionTableSize/12);
    rtSaveIndex             = 0;
    stackSize               = 0;
    rtTargetOffset          = 0;
    status                  = 0;
    checkpoint              = 0;
    addRspGadget            = ADD_RSP_0x38;

    // Load msvcrt (for getchar)
    msvcrt = LoadLibraryA("msvcrt");

    // Load user32 (for MessageBox)
    user32 = LoadLibraryA("User32");
    
    // Load shell32 (for ShellExecute)
    shell32 = LoadLibraryA("Shell32");

    // Init Spoofer Configuration
    custom_memset(&sConfig, 0, sizeof(SPOOFER));

    // Save KernelBaseAddress
    sConfig.KernelBaseAddress = (PVOID)kernelBase;
    // If you're wondering, this is completely useless
    sConfig.KernelBaseAddressEnd = (PVOID)((UINT64)kernelBase + 0x368cc4);
    
    // Configuring random seed
    srand(SEED);

    if (CALL_STACK_TYPE != 1) {
        // The first pop rbp frame is not suitable on most windows versions
        skip_pop_rsp_frame++;
    }

    /*
        SYNTHETIC FRAMES
        - RtlUserThreadStart
        - BaseThreadInitThunk
    */
    PVOID pBaseThreadInitThunk      = (PVOID)GetSymbolAddress(kernel32Base, "BaseThreadInitThunk");
    PVOID pRtlUserThreadStart       = (PVOID)GetSymbolAddress(ntdllBase, "RtlUserThreadStart");

    PRUNTIME_FUNCTION f             = NULL;
    PUNWIND_INFO      ui            = NULL;
    DWORD             stackSizeOf   = 0;

    f = RTFindFunctionByAddress((UINT64)kernel32Base, (UINT64)pBaseThreadInitThunk - (UINT64)kernel32Base);

    if (NULL != f) {
        ui = (PUNWIND_INFO)((UINT64)kernel32Base + (DWORD)f->UnwindData);
        GetStackFrameSizeIgnoringUwopSetFpreg(kernel32Base, (PVOID)ui, &stackSizeOf);
        printf("Function BaseThreadInitThunk found. Stack size: 0x%x - Address: 0x%I64x\n", stackSizeOf, pBaseThreadInitThunk);

        sConfig.BaseThreadInitThunkAddress = (PVOID)pBaseThreadInitThunk;
        sConfig.BaseThreadInitThunkFrameSize = (UINT64)stackSizeOf;

    }
    else {
        printf("Function BaseThreadInitThunk not found\n");
    }

    stackSizeOf = 0;
    f = NULL;
    f = RTFindFunctionByAddress((UINT64)ntdllBase, (UINT64)pRtlUserThreadStart - (UINT64)ntdllBase);

    if (NULL != f) {
        ui = (PUNWIND_INFO)((UINT64)ntdllBase + (DWORD)f->UnwindData);
        GetStackFrameSizeIgnoringUwopSetFpreg(ntdllBase, (PVOID)ui, &stackSizeOf);
        printf("Function RtlUserThreadStart found. Stack size: 0x%x - Address: 0x%I64x\n", stackSizeOf, pRtlUserThreadStart);
        sConfig.RtlUserThreadStartAddress = (PVOID)pRtlUserThreadStart;
        sConfig.RtlUserThreadStartFrameSize = (UINT64)stackSizeOf;

    }
    else {
        printf("Function RtlUserThreadStart not found\n");
    }
    /*
        SYNTHETIC FRAMES - END
    */
    printf("Runtime Function Table Size: %u\n", runtimeFunctionTableSize);
    printf("Runtime Function Table Last Index: %u\n", rtLastIndex);
    printf("RT Function Table Range: 0x%I64X - 0x%I64X\n", (UINT64)pRuntimeFunctionTable, (UINT64)pRuntimeFunctionTable + runtimeFunctionTableSize);
  
    // Example parameters

    if (TARGET == 0) {
        // Config for getchar (No parameter)
        sConfig.SpoofFunctionPointer = (PVOID)GetProcAddress(msvcrt, "getchar");
        sConfig.Nargs = 0;
    }else if (TARGET == 1){    
        // Config for MessageBox (4 parameters: All registers)
        sConfig.SpoofFunctionPointer = (PVOID)GetProcAddress(user32, "MessageBoxA");
        sConfig.Nargs = 4;
        sConfig.Arg01 = NULL;
        sConfig.Arg02 = (PVOID) & "This call was spoofed successfully!";
        sConfig.Arg03 = (PVOID) & "Result of the call";
        sConfig.Arg04 = MB_OK;
    }else if (TARGET == 2){
        // Config for ShellExecuteA (6 parameters: All registers + 2 stack parameters)
        sConfig.SpoofFunctionPointer = (PVOID)GetProcAddress(shell32, "ShellExecuteA");
        sConfig.Nargs = 6;
        sConfig.Arg01 = NULL;
        sConfig.Arg02 = NULL;
        sConfig.Arg03 = (PVOID) & "C:\\Windows\\system32\\notepad.exe\0";
        sConfig.Arg04 = NULL;
        sConfig.Arg05 = NULL;
        sConfig.Arg06 = (PVOID)5;
    }
    else {
        printf("Wrong target %s, specify `#define TARGET [0|1|2]\n", TARGET);
        return;
    }

    // If the call you want to spoof has arguments, please define them here
    // The gadget to restore RSP will get calculated using the number of arguments on the stack
    addRspGadget += ((0x08 * sConfig.Nargs) << 24);

    // Zeroing out near variables
    custom_memset(&addRspGadget, 0, 8);

    // Setting return address
    //returnAddress = (PVOID)_ReturnAddress();
    returnAddress = (PVOID)_AddressOfReturnAddress();

    // Must be given as a stack pointer
    sConfig.ReturnAddress = (PVOID)returnAddress;
    printf("Return address: 0x%I64X\n", sConfig.ReturnAddress);
    
    printf("Address of Function to spoof: 0x%I64X\n", sConfig.SpoofFunctionPointer);
    BYTE test = -1;
    for (int iterations = 0; iterations < 10; iterations++) {

        printf("\n  ------------------------------------ \n");
        // Every time we generate a new random offset
        sConfig.FirstFrameRandomOffset = ((UINT64)rand());
        sConfig.SecondFrameRandomOffset = ((UINT64)rand());

        FindProlog(kernelBase, pRuntimeFunctionTable, rtLastIndex, &stackSize, &rtSaveIndex, &skip_prolog_frame, &rtTargetOffset);
        stackOffsetWhereRbpIsPushed = FindPushRbp(kernelBase, pRuntimeFunctionTable, rtLastIndex, &stackSize, &rtSaveIndex, &skip_pop_rsp_frame, &rtTargetOffset);

        printf("PUSH RBP offset: 0x%X\n", stackOffsetWhereRbpIsPushed);

        FindGadget(kernelBase, pRuntimeFunctionTable, rtLastIndex, &stackSize, &rtSaveIndex, &skip_jmp_gadget, 0);
        FindGadget(kernelBase, pRuntimeFunctionTable, rtLastIndex, &stackSize, &rtSaveIndex, &skip_stack_pivot_gadget, 1);

        SPOOF_CALL(&sConfig);
        Sleep(2000);
    }
}


DWORD FindProlog(HMODULE moduleBase, PERF pRuntimeFunctionTable, DWORD rtLastIndex, PDWORD stackSize, PDWORD prtSaveIndex, PDWORD skip, PDWORD64 rtTargetOffset) {
    PUNWIND_INFO unwindInfo;
    DWORD        status = 0;
    DWORD        suitableFrames = 0;
    *stackSize = 0;

    for (DWORD i = 0; i < rtLastIndex; i++)
    {

        unwindInfo = (PUNWIND_INFO)((UINT64)moduleBase + (DWORD)pRuntimeFunctionTable[i].UnwindData);
        status = GetStackFrameSize(moduleBase, (PVOID)unwindInfo, stackSize);

        if (status != 0) {
            suitableFrames++;
            if (*skip >= suitableFrames) {
                // Let's try another frame
                continue;
            }
            *skip = suitableFrames;

            printf("Breaking at: %d\n", i);
            *prtSaveIndex = i;
            break;
        }
    }

    *rtTargetOffset = (DWORD64)((UINT64)moduleBase + (UINT64)pRuntimeFunctionTable[*prtSaveIndex].BeginAddress);
    sConfig.FirstFrameFunctionPointer = (PVOID)*rtTargetOffset;
    sConfig.FirstFrameSize = *stackSize;
    printf("First Frame FP: 0x%I64X\n", *rtTargetOffset);
    printf("First Frame stack size: 0x%lx\n", *stackSize);

    printf("Return address: 0x%I64X\n", (ULONGLONG)(moduleBase + *stackSize));

    return status;
}


DWORD FindPushRbp(HMODULE moduleBase, PERF pRuntimeFunctionTable, DWORD rtLastIndex, PDWORD stackSize, PDWORD prtSaveIndex, PDWORD skip, PDWORD64 rtTargetOffset) {
    PUNWIND_INFO unwindInfo;
    DWORD        status = 0;
    DWORD        suitableFrames = 0;
    *stackSize = 0;

    for (DWORD i = 0; i < rtLastIndex; i++)
    {

        unwindInfo = (PUNWIND_INFO)((UINT64)moduleBase + (DWORD)pRuntimeFunctionTable[i].UnwindData);
        status = GetStackFrameSizeWhereRbpIsPushedOnStack(moduleBase, (PVOID)unwindInfo, stackSize);

        if (0 != status) {

            suitableFrames++;
            if (*skip >= suitableFrames) {
                // Let's try another frame
                continue;
            }
            *skip = suitableFrames;
            printf("Breaking at: %d\n", i);
            *prtSaveIndex = i;
            break;
        }
    }

    *rtTargetOffset = (DWORD64)((UINT64)moduleBase + (UINT64)pRuntimeFunctionTable[*prtSaveIndex].BeginAddress);
    sConfig.SecondFrameFunctionPointer = (PVOID)*rtTargetOffset;
    sConfig.SecondFrameSize = *stackSize;
    sConfig.StackOffsetWhereRbpIsPushed = status;

    printf("Second Frame FP: 0x%I64X\n", *rtTargetOffset);
    printf("Second Frame stack size: 0x%lx\n", *stackSize);

    printf("Return address: 0x%I64X\n", (ULONGLONG)(moduleBase + *stackSize));


    return status;
}


VOID FindGadget(HMODULE moduleBase, PERF pRuntimeFunctionTable, DWORD rtLastIndex, PDWORD stackSize, PDWORD prtSaveIndex, PDWORD skip, DWORD gadgetType) {
    DWORD           gadgets = 0;
    DWORD           status;
    PUNWIND_INFO    unwindInfo;
    DWORD           addRspGadget = ADD_RSP_0x38;

    // In case we are building an artificial call stack
    if(CALL_STACK_TYPE == 1){
        addRspGadget += ((0x08 * sConfig.Nargs) << 24);
    }

    for (DWORD i = 0; i < rtLastIndex; i++)
    {
        BOOL gadgetFound = FALSE;
        for (UINT64 j = (UINT64)moduleBase + pRuntimeFunctionTable[i].BeginAddress; j < (UINT64)moduleBase + pRuntimeFunctionTable[i].EndAddress; j++) {

            if ((*(DWORD*)j == addRspGadget && *(BYTE*)(j + 4) == RET && gadgetType == 1) || (*(WORD*)j == JMP_RBX && gadgetType == 0)) {

                *stackSize = 0;
                unwindInfo = (PUNWIND_INFO)((UINT64)moduleBase + (DWORD)pRuntimeFunctionTable[i].UnwindData);
                status = GetStackFrameSizeIgnoringUwopSetFpreg(moduleBase, (PVOID)unwindInfo, stackSize);

                if (status != 0) {
                    gadgets++;
                    if (*skip >= gadgets) {
                        // Let's try another gadget
                        continue;
                    }
                    *skip = gadgets;

                    if (gadgetType == 1){
                        sConfig.AddRspXGadget = (PVOID)j;
                        sConfig.AddRspXGadgetFrameSize = *stackSize;
                        gadgetFound = TRUE;
                        *prtSaveIndex = i;
                        printf("Breaking at: %d         \n", i);
                        printf("Gadget Address: 0x%I64X  \n", j);
                        printf("ADD RSP, X Frame Stack size: 0x%lx \n", *stackSize);
                    }
                    else {
                        sConfig.JmpRbxGadget = (PVOID)j;
                        sConfig.JmpRbxGadgetFrameSize = *stackSize;
                        gadgetFound = TRUE;
                        *prtSaveIndex = i;
                        printf("Breaking at: %d\n", i);
                        printf("Gadget Address: 0x%I64X\n", j);
                        printf("JMP [RBX] Frame Stack size: 0x%lx\n", *stackSize);
                    }
                    break;
                }
            }
        }
        if (gadgetFound) {
            break;
        }
    }


}


// Wrapper function: DO NOT USE
VOID SpoofCallStack(PSPOOFER psConfig) {

    // _ReturnAddress intrinsic doesn't work as expected, use _AddressOfReturnAddress instead
    psConfig->ReturnAddress = _AddressOfReturnAddress();
    spoof_call(psConfig);
}

DWORD GetStackFrameSizeWhereRbpIsPushedOnStack(HMODULE moduleBase, PVOID unwindInfoAddress, DWORD* targetStackOffset) {

    DWORD               saveStackOffset;
    DWORD               backupStackOffset;
    DWORD               frameOffsets[MAX_FRAMES];
    PRUNTIME_FUNCTION   pChainedFunction;

    BOOL                RBP_PUSHED          = FALSE;
    PUNWIND_INFO        unwindInfo          = (PUNWIND_INFO)unwindInfoAddress;
    PUNWIND_CODE        unwindCode          = (PUNWIND_CODE)unwindInfo->UnwindCode;
    MIN_CTX             ctx                 = MIN_CTX();
    DWORD               frameSize           = 0;
    DWORD               nodeIndex           = 0;
    DWORD               countOfCodes        = unwindInfo->CountOfCodes;
    
    saveStackOffset                         = 0;
    *targetStackOffset                      = 0;
    backupStackOffset                       = *targetStackOffset;

    // Initialise context
    custom_memset(&ctx, 0, sizeof(MIN_CTX));
    // printf("The stack is now 0x%I64X\n", *targetOffset); 

    while (nodeIndex < countOfCodes) {
        // Ensure frameSize is reset
        frameSize = 0;

        switch (unwindCode->UnwindOp) {

        case UWOP_PUSH_NONVOL: // 0

            if (unwindCode->OpInfo == RSP) {
                // We break here
                return 0;
            }
            if (unwindCode->OpInfo == RBP && RBP_PUSHED) {
                return 0;
            }
            else if (unwindCode->OpInfo == RBP) {
                saveStackOffset = *targetStackOffset;
                RBP_PUSHED = 1;
            }

            *targetStackOffset += 8;
            break;

        case UWOP_ALLOC_LARGE: // 1
            // If the operation info equals 0 -> allocation size / 8 in next slot
            // If the operation info equals 1 -> unscaled allocation size in next 2 slots
            // In any case, we need to advance 1 slot and record the size

            // Skip to next Unwind Code
            unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
            DPRINTUNWINDCODE(unwindCode);

            // Keep track of current node
            nodeIndex++;
            // Register size in next slot
            frameSize = unwindCode->FrameOffset;

            if (unwindCode->OpInfo == 0) {
                // If the operation info equals 0, then the size of the allocation divided by 8 
                // is recorded in the next slot, allowing an allocation up to 512K - 8.
                // We already advanced of 1 slot, and recorded the allocation size
                // We just need to multiply it for 8 to get the unscaled allocation size
                frameSize *= 8;
            }
            else
            {
                // If the operation info equals 1, then the unscaled size of the allocation is 
                // recorded in the next two slots in little-endian format, allowing allocations 
                // up to 4GB - 8.
                // Skip to next Unwind Code
                unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
                // Keep track of current node
                nodeIndex++;
                // Unmask the rest of the allocation size
                frameSize += unwindCode->FrameOffset << 16;

            }
            DPRINT("Final Frame Size: 0x%x\n", frameSize);
            *targetStackOffset += frameSize;
            break;

        case UWOP_ALLOC_SMALL: // 2

            // Allocate a small-sized area on the stack. The size of the allocation is the operation 
            // info field * 8 + 8, allowing allocations from 8 to 128 bytes.
            *targetStackOffset += 8 * (unwindCode->OpInfo + 1);
            break;


        case UWOP_SET_FPREG: // 3
            return 0;
            break; // EARLY RET

        case UWOP_SAVE_NONVOL: // 4
            // Save a nonvolatile integer register on the stack using a MOV instead of a PUSH. This code is 
            // primarily used for shrink-wrapping, where a nonvolatile register is saved to the stack in a position 
            // that was previously allocated. The operation info is the number of the register. The scaled-by-8 
            // stack offset is recorded in the next unwind operation code slot, as described in the note above.
            if (unwindCode->OpInfo == RSP) {
                // This time, we return only if RSP was saved
                return 0;
            }
            else
            {
                // For future use: save the scaled by 8 stack offset
                *((ULONG*)&ctx + unwindCode->OpInfo) = *targetStackOffset + (DWORD)((PUNWIND_CODE)((PWORD)unwindCode + 1))->FrameOffset * 8;
                DPRINTCTX(ctx);

                // Skip to next Unwind Code
                unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
                nodeIndex++;

                if (unwindCode->OpInfo != RBP) {
                    // Restore original stack size (!?)
                    *targetStackOffset = backupStackOffset;
                    break;
                }
                if (RBP_PUSHED) {
                    return 0;
                }

                RBP_PUSHED = TRUE;
                // We save the stack offset where MOV [RSP], RBP happened
                // During unwinding, this address will be popped back in RBP
                saveStackOffset = *((ULONG*)&ctx + unwindCode->OpInfo);

                // Restore original stack size (!?)
                *targetStackOffset = backupStackOffset;
            }

            break;
        case UWOP_SAVE_NONVOL_BIG: // 5
            // Save a nonvolatile integer register on the stack with a long offset, using a MOV instead of a PUSH. 
            // This code is primarily used for shrink-wrapping, where a nonvolatile register is saved to the stack 
            // in a position that was previously allocated. The operation info is the number of the register. 
            // The unscaled stack offset is recorded in the next two unwind operation code slots, as described 
            // in the note above.
            if (unwindCode->OpInfo == RSP) {
                return 0;
            }

            // For future use
            *((ULONG*)&ctx + unwindCode->OpInfo) = *targetStackOffset + (DWORD)((PUNWIND_CODE)((PWORD)unwindCode + 1))->FrameOffset;
            *((ULONG*)&ctx + unwindCode->OpInfo) += (DWORD)((PUNWIND_CODE)((PWORD)unwindCode + 2))->FrameOffset << 16;

            if (unwindCode->OpInfo != RBP) {
                // Restore original stack size (!?)
                *targetStackOffset = backupStackOffset;
                break;
            }
            if (RBP_PUSHED) {
                return 0;
            }
            // We save the stack offset where MOV [RSP], RBP happened
            // During unwinding, this address will be popped back in RBP
            saveStackOffset = *((ULONG*)&ctx + unwindCode->OpInfo);
            // Restore Stack Size
            *targetStackOffset = backupStackOffset;

            // Skip the other two nodes used for this unwind operation
            unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 2);
            nodeIndex += 2;

            DPRINTCTX(ctx);
            break;

        case UWOP_EPILOG:            // 6
        case UWOP_SAVE_XMM128:       // 8
            // Save all 128 bits of a nonvolatile XMM register on the stack. The operation info is the number of 
            // the register. The scaled-by-16 stack offset is recorded in the next slot.

            // TODO: Handle this

            // Skip to next Unwind Code
            unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
            nodeIndex++;
            break;
        case UWOP_SPARE_CODE:        // 7
        case UWOP_SAVE_XMM128BIG:    // 9
            // Save all 128 bits of a nonvolatile XMM register on the stack with a long offset. The operation info 
            // is the number of the register. The unscaled stack offset is recorded in the next two slots.

            // TODO: Handle this

            // Advancing next 2 nodes
            unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 2);
            nodeIndex += 2;
            break;
        case UWOP_PUSH_MACH_FRAME:    // 10
            // Push a machine frame. This unwind code is used to record the effect of a hardware interrupt or exception. 
            // There are two forms.

            // NOTE: UNTESTED
            // TODO: Test this
            if (unwindCode->OpInfo == 0) {
                *targetStackOffset += 0x40;
            }
            else {
                *targetStackOffset += 0x48;
            }
            break;
        }

        unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
        nodeIndex++;
    }

    // If chained unwind information is present then we need to
    // also recursively parse this and add to total stack size.
    if (BitChainInfo(unwindInfo->Flags))
    {
        nodeIndex = unwindInfo->CountOfCodes;
        if (0 != (nodeIndex & 1))
        {
            nodeIndex += 1;
        }
        pChainedFunction = (PRUNTIME_FUNCTION)(&unwindInfo->UnwindCode[nodeIndex]);
        return GetStackFrameSize(moduleBase, (PUNWIND_INFO)((UINT64)moduleBase + (DWORD)pChainedFunction->UnwindData), targetStackOffset);
    }

    return saveStackOffset;


}

DWORD GetStackFrameSizeIgnoringUwopSetFpreg(HMODULE moduleBase, PVOID unwindInfoAddress, DWORD* targetStackOffset) {

    DWORD               saveStackOffset;
    DWORD               backupStackOffset;
    DWORD               frameOffsets[MAX_FRAMES];
    PRUNTIME_FUNCTION   pChainedFunction;

    PUNWIND_INFO        unwindInfo          = (PUNWIND_INFO)unwindInfoAddress;
    PUNWIND_CODE        unwindCode          = (PUNWIND_CODE)unwindInfo->UnwindCode;
    MIN_CTX             ctx                 = MIN_CTX();
    DWORD               frameSize           = 0;
    DWORD               nodeIndex           = 0;
    DWORD               countOfCodes        = unwindInfo->CountOfCodes;

    saveStackOffset                         = 0;
    *targetStackOffset                      = 0;
    backupStackOffset                       = *targetStackOffset;

    // Initialise context
    custom_memset(&ctx, 0, sizeof(MIN_CTX));
    // printf("The stack is now 0x%I64X\n", *targetOffset);

    while (nodeIndex < countOfCodes) {
        // Ensure frameSize is reset
        frameSize = 0;

        switch (unwindCode->UnwindOp) {

        case UWOP_PUSH_NONVOL: // 0

            if (unwindCode->OpInfo == RSP) {
                // We break here
                return 0;
            }
            *targetStackOffset += 8;
            break;

        case UWOP_ALLOC_LARGE: // 1
            // If the operation info equals 0 -> allocation size / 8 in next slot
            // If the operation info equals 1 -> unscaled allocation size in next 2 slots
            // In any case, we need to advance 1 slot and record the size

            // Skip to next Unwind Code
            unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
            DPRINTUNWINDCODE(unwindCode);

            // Keep track of current node
            nodeIndex++;
            // Register size in next slot
            frameSize = unwindCode->FrameOffset;

            if (unwindCode->OpInfo == 0) {
                // If the operation info equals 0, then the size of the allocation divided by 8 
                // is recorded in the next slot, allowing an allocation up to 512K - 8.
                // We already advanced of 1 slot, and recorded the allocation size
                // We just need to multiply it for 8 to get the unscaled allocation size
                frameSize *= 8;
            }
            else
            {
                // If the operation info equals 1, then the unscaled size of the allocation is 
                // recorded in the next two slots in little-endian format, allowing allocations 
                // up to 4GB - 8.
                // Skip to next Unwind Code
                unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
                // Keep track of current node
                nodeIndex++;
                // Unmask the rest of the allocation size
                frameSize += unwindCode->FrameOffset << 16;

            }
            DPRINT("Final Frame Size: 0x%x\n", frameSize);
            *targetStackOffset += frameSize;
            break;

        case UWOP_ALLOC_SMALL: // 2

            // Allocate a small-sized area on the stack. The size of the allocation is the operation 
            // info field * 8 + 8, allowing allocations from 8 to 128 bytes.
            *targetStackOffset += 8 * (unwindCode->OpInfo + 1);
            break;


        case UWOP_SET_FPREG: // 3
            // IGNORED
            break;

        case UWOP_SAVE_NONVOL: // 4
            // Save a nonvolatile integer register on the stack using a MOV instead of a PUSH. This code is 
            // primarily used for shrink-wrapping, where a nonvolatile register is saved to the stack in a position 
            // that was previously allocated. The operation info is the number of the register. The scaled-by-8 
            // stack offset is recorded in the next unwind operation code slot, as described in the note above.
            if (unwindCode->OpInfo == RSP) {
                // This time, we return only if RSP was saved
                return 0;
            }
            else
            {
                // For future use: save the scaled by 8 stack offset
                *((ULONG*)&ctx + unwindCode->OpInfo) = *targetStackOffset + (DWORD)((PUNWIND_CODE)((PWORD)unwindCode + 1))->FrameOffset * 8;
                DPRINTCTX(ctx);

                // Skip to next Unwind Code
                unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
                nodeIndex++;

                // We save the stack offset where MOV [RSP], RBP happened
                // During unwinding, this address will be popped back in RBP
                saveStackOffset = *((ULONG*)&ctx + unwindCode->OpInfo);

                // Restore original stack size (!?)
                *targetStackOffset = backupStackOffset;
            }

            break;
        case UWOP_SAVE_NONVOL_BIG: // 5
            // Save a nonvolatile integer register on the stack with a long offset, using a MOV instead of a PUSH. 
            // This code is primarily used for shrink-wrapping, where a nonvolatile register is saved to the stack 
            // in a position that was previously allocated. The operation info is the number of the register. 
            // The unscaled stack offset is recorded in the next two unwind operation code slots, as described 
            // in the note above.
            if (unwindCode->OpInfo == RSP) {
                return 0;
            }

            // For future use
            *((ULONG*)&ctx + unwindCode->OpInfo) = *targetStackOffset + (DWORD)((PUNWIND_CODE)((PWORD)unwindCode + 1))->FrameOffset;
            *((ULONG*)&ctx + unwindCode->OpInfo) += (DWORD)((PUNWIND_CODE)((PWORD)unwindCode + 2))->FrameOffset << 16;

            // We save the stack offset where MOV [RSP], RBP happened
            // During unwinding, this address will be popped back in RBP
            saveStackOffset = *((ULONG*)&ctx + unwindCode->OpInfo);
            // Restore Stack Size
            *targetStackOffset = backupStackOffset;

            // Skip the other two nodes used for this unwind operation
            unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 2);
            nodeIndex += 2;

            DPRINTCTX(ctx);
            break;

        case UWOP_EPILOG:            // 6
        case UWOP_SAVE_XMM128:       // 8
            // Save all 128 bits of a nonvolatile XMM register on the stack. The operation info is the number of 
            // the register. The scaled-by-16 stack offset is recorded in the next slot.

            // TODO: Handle this

            // Skip to next Unwind Code
            unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
            nodeIndex++;
            break;
        case UWOP_SPARE_CODE:        // 7
        case UWOP_SAVE_XMM128BIG:    // 9
            // Save all 128 bits of a nonvolatile XMM register on the stack with a long offset. The operation info 
            // is the number of the register. The unscaled stack offset is recorded in the next two slots.

            // TODO: Handle this

            // Advancing next 2 nodes
            unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 2);
            nodeIndex += 2;
            break;
        case UWOP_PUSH_MACH_FRAME:    // 10
            // Push a machine frame. This unwind code is used to record the effect of a hardware interrupt or exception. 
            // There are two forms. 

            // NOTE: UNTESTED
            // TODO: Test this
            if (unwindCode->OpInfo == 0) {
                *targetStackOffset += 0x40;
            }
            else {
                *targetStackOffset += 0x48;
            }
            break;
        }

        unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
        nodeIndex++;
    }

    // If chained unwind information is present then we need to
    // also recursively parse this and add to total stack size.
    if (BitChainInfo(unwindInfo->Flags))
    {
        nodeIndex = unwindInfo->CountOfCodes;
        if (0 != (nodeIndex & 1))
        {
            nodeIndex += 1;
        }
        pChainedFunction = (PRUNTIME_FUNCTION)(&unwindInfo->UnwindCode[nodeIndex]);
        return GetStackFrameSizeIgnoringUwopSetFpreg(moduleBase, (PUNWIND_INFO)((UINT64)moduleBase + (DWORD)pChainedFunction->UnwindData), targetStackOffset);
    }

    return *targetStackOffset;


}

DWORD GetStackFrameSize(HMODULE hModule, PVOID unwindInfoAddress, DWORD* targetStackOffset) {

    UINT64              saveID;
    DWORD               frameOffsets[MAX_FRAMES];
    PRUNTIME_FUNCTION   pChainedFunction;
    USHORT              _fo;

    DWORD               frameSize           = 0;
    DWORD               nodeIndex           = 0;
    BOOL                UWOP_SET_FPREG_HIT  = FALSE;
    PUNWIND_INFO        unwindInfo          = (PUNWIND_INFO)unwindInfoAddress;
    PUNWIND_CODE        unwindCode          = (PUNWIND_CODE)unwindInfo->UnwindCode;
    MIN_CTX             ctx                 = MIN_CTX();

    // Restore Stack Size
    *targetStackOffset                      = 0;

    // Initialise context
    custom_memset(&ctx, 0, sizeof(MIN_CTX));
    // printf("The stack is now 0x%I64X\n", *targetOffset);

    while(nodeIndex < unwindInfo->CountOfCodes){
        // Ensure frameSize is reset
        frameSize = 0;

        switch (unwindCode->UnwindOp) {
    
        case UWOP_PUSH_NONVOL: // 0
            
            if (unwindCode->OpInfo == RSP && !UWOP_SET_FPREG_HIT) {
                // We break here
                return 0;
            }
            *targetStackOffset += 8;
            break;

        case UWOP_ALLOC_LARGE: // 1
            // If the operation info equals 0 -> allocation size / 8 in next slot
            // If the operation info equals 1 -> unscaled allocation size in next 2 slots
            // In any case, we need to advance 1 slot and record the size

            // Skip to next Unwind Code
            unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
            DPRINTUNWINDCODE(unwindCode);

            // Keep track of current node
            nodeIndex++;
            // Register size in next slot
            frameSize = unwindCode->FrameOffset;

            if (unwindCode->OpInfo == 0) {
                // If the operation info equals 0, then the size of the allocation divided by 8 
                // is recorded in the next slot, allowing an allocation up to 512K - 8.
                // We already advanced of 1 slot, and recorded the allocation size
                // We just need to multiply it for 8 to get the unscaled allocation size
                frameSize *= 8;
            }
            else 
            {
                // If the operation info equals 1, then the unscaled size of the allocation is 
                // recorded in the next two slots in little-endian format, allowing allocations 
                // up to 4GB - 8.
                // Skip to next Unwind Code
                unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
                // Keep track of current node
                nodeIndex++;
                // Unmask the rest of the allocation size
                frameSize += unwindCode->FrameOffset << 16;

            }
            DPRINT("Final Frame Size: 0x%x\n", frameSize);
            *targetStackOffset += frameSize;
            break;

        case UWOP_ALLOC_SMALL: // 2

            // Allocate a small-sized area on the stack. The size of the allocation is the operation 
            // info field * 8 + 8, allowing allocations from 8 to 128 bytes.
            *targetStackOffset += 8 * (unwindCode->OpInfo + 1);
            break;


        case UWOP_SET_FPREG: // 3
            // Establish the frame pointer register by setting the register to some offset of the current RSP. 
            // The offset is equal to the Frame Register offset (scaled) field in the UNWIND_INFO * 16, allowing 
            // offsets from 0 to 240. The use of an offset permits establishing a frame pointer that points to the
            // middle of the fixed stack allocation, helping code density by allowing more accesses to use short 
            // instruction forms. The operation info field is reserved and shouldn't be used.

            if (BitEHandler(unwindInfo->Flags) && BitChainInfo(unwindInfo->Flags)) {
                return 0;
            }

            UWOP_SET_FPREG_HIT  = TRUE;

            frameSize           = -0x10 * (unwindInfo->FrameOffset);
            *targetStackOffset += frameSize;
            break;


        case UWOP_SAVE_NONVOL: // 4
            // Save a nonvolatile integer register on the stack using a MOV instead of a PUSH. This code is 
            // primarily used for shrink-wrapping, where a nonvolatile register is saved to the stack in a position 
            // that was previously allocated. The operation info is the number of the register. The scaled-by-8 
            // stack offset is recorded in the next unwind operation code slot, as described in the note above.
            if (unwindCode->OpInfo == RBP || unwindCode->OpInfo == RSP) {
                return 0;
            }
            // Skip to next Unwind Code
            unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
            nodeIndex++;
                
            // For future use
            *((ULONG*)&ctx + unwindCode->OpInfo) = *targetStackOffset + (DWORD)((PUNWIND_CODE)((PWORD)unwindCode + 1))->FrameOffset * 8;
            DPRINTCTX(ctx);
                            
            break;
        case UWOP_SAVE_NONVOL_BIG: // 5
            // Save a nonvolatile integer register on the stack with a long offset, using a MOV instead of a PUSH. 
            // This code is primarily used for shrink-wrapping, where a nonvolatile register is saved to the stack 
            // in a position that was previously allocated. The operation info is the number of the register. 
            // The unscaled stack offset is recorded in the next two unwind operation code slots, as described 
            // in the note above.
            if (unwindCode->OpInfo == RBP || unwindCode->OpInfo == RSP) {
                return 0;
            }

            // For future use
            *((ULONG*)&ctx + unwindCode->OpInfo) = *targetStackOffset + (DWORD)((PUNWIND_CODE)((PWORD)unwindCode + 1))->FrameOffset;
            *((ULONG*)&ctx + unwindCode->OpInfo) += (DWORD)((PUNWIND_CODE)((PWORD)unwindCode + 2))->FrameOffset << 16;
            
            // Skip the other two nodes used for this unwind operation
            unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 2);
            nodeIndex += 2;

            DPRINTCTX(ctx);
            break;

        case UWOP_EPILOG:            // 6
        case UWOP_SAVE_XMM128:       // 8
            // Save all 128 bits of a nonvolatile XMM register on the stack. The operation info is the number of 
            // the register. The scaled-by-16 stack offset is recorded in the next slot.
            
            // TODO: Handle this
            
            // Skip to next Unwind Code
            unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
            nodeIndex++;
            break;
        case UWOP_SPARE_CODE:        // 7
        case UWOP_SAVE_XMM128BIG:    // 9
            // Save all 128 bits of a nonvolatile XMM register on the stack with a long offset. The operation info 
            // is the number of the register. The unscaled stack offset is recorded in the next two slots.
            
            // TODO: Handle this
            
            // Advancing next 2 nodes
            unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 2);
            nodeIndex += 2;
            break;
        case UWOP_PUSH_MACH_FRAME:    // 10
            // Push a machine frame. This unwind code is used to record the effect of a hardware interrupt or exception. 
            // There are two forms.
            
            // NOTE: UNTESTED
            // TODO: Test this
            if (unwindCode->OpInfo == 0) {
                *targetStackOffset += 0x40;
            }
            else {
                *targetStackOffset += 0x48;
            }
            break;
        }
        
        unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
        nodeIndex++;
    }

    // If chained unwind information is present then we need to
    // also recursively parse this and add to total stack size.
    if (BitChainInfo(unwindInfo->Flags))
    {
        nodeIndex = unwindInfo->CountOfCodes;
        if (0 != (nodeIndex & 1))
        {
            nodeIndex += 1;
        }
        pChainedFunction = (PRUNTIME_FUNCTION)(&unwindInfo->UnwindCode[nodeIndex]);        
        return GetStackFrameSize(hModule, (PUNWIND_INFO)((UINT64)hModule + (DWORD)pChainedFunction->UnwindData), targetStackOffset);
    }

    return UWOP_SET_FPREG_HIT;
    

}


/*********************************************************************************

    HELPER FUNCTIONS

*********************************************************************************/


void LookupSymbolFromRTIndex(HMODULE dllBase, int rtFuntionIndex, bool verbose) {


    PIMAGE_RUNTIME_FUNCTION_ENTRY rtFunction = RTFindFunctionByIndex((UINT64)dllBase, rtFuntionIndex);

    if (rtFunction == NULL) {
        printf("Function not found\n");
        return;
    }

    if (verbose) {
        printf("Function found:             \n");
        printf("  Begin Address 0x%p        \n", (PVOID)rtFunction->BeginAddress);
        printf("  End Address 0x%p          \n", (PVOID)rtFunction->EndAddress);
        printf("  Unwind Info Address 0x%p  \n", (PVOID)rtFunction->UnwindInfoAddress);
        printf("Looking up in exports...    \n");
    }
    char* procName = GetSymbolNameByOffset(dllBase, rtFunction->BeginAddress);

    if (procName == NULL) {
        if (verbose) {
            printf("Function not found\n");
        }
        return;
    }

    printf("Function %u found: %s\n", rtFuntionIndex, procName);

    if (verbose) {
        PrintUnwindInfo(dllBase, (PVOID)rtFunction->UnwindData);
    }

    return;
}

void PrintUnwindInfo(HMODULE dllBase, PVOID unwindDataAddress) {

    PUNWIND_INFO tInfo = (PUNWIND_INFO)((UINT64)dllBase + (DWORD)unwindDataAddress);

    printf("    Version: %d             \n", Version(tInfo->Flags));
    printf("    Ver + Flags: " B2BP "   \n", BYTE_TO_BINARY(tInfo->Flags));
    printf("    SizeOfProlog: 0x%x      \n", tInfo->SizeOfProlog);
    printf("    CountOfCodes: 0x%x      \n", tInfo->CountOfCodes);
    printf("    FrameRegister: 0x%x     \n", tInfo->FrameRegister);
    printf("    FrameOffset: 0x%x       \n", tInfo->FrameOffset);

    for (int j = 0; j < tInfo->CountOfCodes; j++) {
        printf("    UnwindCode [%d]     \n", j);
        printf("      Frame Offset: 0x%x\n", tInfo->UnwindCode[j].FrameOffset);
        printf("      Code Offset: 0x%x \n", tInfo->UnwindCode[j].CodeOffset);
        printf("      UnwindOp: 0x%x    \n", tInfo->UnwindCode[j].UnwindOp);
        printf("      UnwindOpInfo: 0x%x\n", tInfo->UnwindCode[j].OpInfo);
    }

    if (BitChainInfo(tInfo->Flags)) {
        printf("    Function Entry Offset: 0x%p\n", GetChainedFunctionEntry(dllBase, tInfo));
    }
    if (BitUHandler(tInfo->Flags)) {

    }
    if (BitEHandler(tInfo->Flags)) {
        PVOID dataPtr = GetExceptionDataPtr(tInfo);
        PVOID handlerPtr = GetExceptionHandler(dllBase, tInfo);
        ULONG data = *((PULONG)dataPtr);
        INT32 handler = *((PDWORD)handlerPtr);

        printf("    Exception Handler Offset: 0x%p\n", GetExceptionHandler(dllBase, tInfo));
        printf("    Exception Data Offset: 0x%x\n", data);
    }

    return;
}

void EnumAllRTFunctions(HMODULE moduleBase)
{
    DWORD                   tSize;
    PRUNTIME_FUNCTION       pRuntimeFunctionTable;
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory;

    pRuntimeFunctionTable = (PRUNTIME_FUNCTION)(GetExceptionDirectoryAddress(moduleBase, &tSize));

    for (DWORD i = 0; i <= 5038; i++)
    {
        /*
        PRUNTIME_FUNCTION rtft = (PRUNTIME_FUNCTION)(imageExportDirectory + 0xc*i);

        */

        printf("Runtime Function %u \n", i);
        printf("  Begin Address 0x%p\n  End Address 0x%p\n  Unwind Info Address 0x%p\n",
            (PVOID)pRuntimeFunctionTable[i].BeginAddress,
            (PVOID)pRuntimeFunctionTable[i].EndAddress,
            (PVOID)pRuntimeFunctionTable[i].UnwindInfoAddress);

        PrintUnwindInfo(moduleBase, (PVOID)pRuntimeFunctionTable[i].UnwindData);

    }
    // printf(BYTE_TO_BINARY_PATTERN"\n", BYTE_TO_BINARY(UBYTE(UNW_FLAG_CHAININFO | UNW_FLAG_UHANDLER|  UNW_FLAG_EHANDLER )));

}


PIMAGE_RUNTIME_FUNCTION_ENTRY RTFindFunctionByAddress(UINT64 modulelBase, DWORD64 functionOffset) {

    DWORD                   tSize;
    PRUNTIME_FUNCTION       pRuntimeFunctionTable;
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory;

    pRuntimeFunctionTable = (PRUNTIME_FUNCTION)(GetExceptionDirectoryAddress((HMODULE)modulelBase, &tSize));
    pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(GetExportDirectoryAddress((HMODULE)modulelBase));

    for (DWORD i = 0; i < pImageExportDirectory->NumberOfFunctions; i++)
    {
        if (pRuntimeFunctionTable[i].BeginAddress == functionOffset) {

            return pRuntimeFunctionTable + i;
        }
    }
    return NULL;
}

PIMAGE_RUNTIME_FUNCTION_ENTRY RTFindFunctionByIndex(UINT64 kernelBase, DWORD index) {

    DWORD                   tSize;
    PRUNTIME_FUNCTION       pRuntimeFunctionTable;
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory;

    pRuntimeFunctionTable = (PRUNTIME_FUNCTION)(GetExceptionDirectoryAddress((HMODULE)kernelBase, &tSize));
    pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(GetExportDirectoryAddress((HMODULE)kernelBase));

    return pRuntimeFunctionTable + index;
}

DWORD FindRTFunctionsUnwind(HMODULE moduleBase, PVOID tUnwindCodeAddress) {

    DWORD               tSize;
    PUNWIND_CODE        tUnwindCode;
    PUNWIND_INFO        unwindInfo;
    PRUNTIME_FUNCTION   pRuntimeFunctionTable;

    tUnwindCode = (PUNWIND_CODE)tUnwindCodeAddress;
    pRuntimeFunctionTable = (PRUNTIME_FUNCTION)(GetExceptionDirectoryAddress(moduleBase, &tSize));

    for (DWORD i = 0; i <= 5038; i++)
    {

        unwindInfo = (PUNWIND_INFO)((UINT64)moduleBase + (DWORD)pRuntimeFunctionTable[i].UnwindData);
        for (int j = 0; j < unwindInfo->CountOfCodes; j++) {

            if (unwindInfo->UnwindCode[j].FrameOffset == tUnwindCode->FrameOffset) {

                printf("Found frame offset with Runtime Function: %u, unwindCode: %u   \n", i + 1, j);
                printf("Found: 0x%x - Expected: 0x%x                                   \n", unwindInfo->UnwindCode[j].FrameOffset, tUnwindCode->FrameOffset);
                printf("Address in module: 0x%p                                        \n", (PVOID)((UINT64)moduleBase + (DWORD)pRuntimeFunctionTable[i].BeginAddress));

                return i;

            }

            // TODO: Implement the rest after

        }

    }
    printf("Function not found\n");

    return 0;

}

/*********************************************************************************

    TESTING FUNCTIONS

*********************************************************************************/


void TestLookupByFrameOffset() {
    UNWIND_CODE tUnwindCode;
    HMODULE     kernelBase;
    DWORD       offset;

    tUnwindCode.FrameOffset = 0x2313;
    kernelBase = (HMODULE)GetModule(KERNELBASE_HASH);
    offset = FindRTFunctionsUnwind(kernelBase, &tUnwindCode);

    LookupSymbolFromRTIndex(kernelBase, offset, TRUE);
}

void TestLocateFunctionByAddress() {
    PERF         rtFunction;
    HMODULE      kernelBase;
    UINT64       procOffset;
    PUNWIND_INFO tInfo;

    kernelBase = (HMODULE)GetModule(KERNELBASE_HASH);
    procOffset = GetSymbolOffset(kernelBase, "Internal_EnumSystemLocales");
    rtFunction = RTFindFunctionByAddress((UINT64)kernelBase, procOffset);

    printf("Function Offset: 0x%I64X\n", (ULONGLONG)procOffset);

    if (rtFunction == NULL) {
        printf("Function not found\n");
        return;
    }
    printf("Function found: \n");
    printf("  Begin Address 0x%p\n  End Address 0x%p\n  Unwind Info Address 0x%p\n", (PVOID)rtFunction->BeginAddress, (PVOID)rtFunction->EndAddress, (PVOID)rtFunction->UnwindInfoAddress);

    tInfo = (PUNWIND_INFO)((UINT64)kernelBase + (DWORD)rtFunction->UnwindData);

    PrintUnwindInfo(kernelBase, (PVOID)rtFunction->UnwindData);
}

void TestEnumAllRT(DWORD moduleHash) {
    EnumAllRTFunctions((HMODULE)GetModule(moduleHash));
}

void Test()
{
    PERF         rtFunction;
    PERF         rtFunction2;
    HMODULE      kernelBase;
    HMODULE      ntdllBase;
    HMODULE      mainModule;
    UINT64       procOffset;
    PUNWIND_INFO tInfo;
    UINT         errc;
    LPCSTR       tFunction;

    kernelBase = (HMODULE)GetModule(KERNELBASE_HASH);
    ntdllBase = (HMODULE)GetModule(NTDLL_HASH);
    mainModule = GetModuleHandle(NULL);
    errc = 0;
    tFunction = "UrlHashW";
    /*
    tFunction  = "SystemTimeToTzSpecificLocalTimeEx";
    tFunction  = "NtWriteVirtualMemory";
    tFunction  = "CreatePrivateObjectSecurity";
    */

    procOffset = GetSymbolOffset(kernelBase, tFunction);
    rtFunction = RTFindFunctionByAddress((UINT64)kernelBase, procOffset);
    if (rtFunction == NULL) {
        printf("Function not found\n");
        return;
    }

    printf("Function Offset: 0x%I64X\n", procOffset);
    printf("Function %s found: \n", tFunction);
    printf("  Begin Address 0x%p\n  End Address 0x%p\n  Unwind Info Address 0x%p\n", (PVOID)rtFunction->BeginAddress, (PVOID)rtFunction->EndAddress, (PVOID)rtFunction->UnwindInfoAddress);

    tInfo = (PUNWIND_INFO)((UINT64)kernelBase + (DWORD)rtFunction->UnwindData);
    PrintUnwindInfo(kernelBase, (PVOID)rtFunction->UnwindData);
    GetStackFrameSize(kernelBase, tInfo, NULL);
    return;
}