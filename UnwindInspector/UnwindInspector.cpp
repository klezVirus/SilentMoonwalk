#include "include/Common.h"
#include "include/Functions.h"

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
    printf("    UnwindCodes:            \n");

    char* reg = NULL;
    
    for (int j = 0; j < tInfo->CountOfCodes; j++) {
        printf("    [%.2xh] Frame: 0x%.4x - ", j, tInfo->UnwindCode[j].FrameOffset);
        reg = GetOpInfo(tInfo->UnwindCode[j].OpInfo);

        switch (tInfo->UnwindCode[j].UnwindOp) {

        case UWOP_PUSH_NONVOL: // 0
            printf("0x%.2x  - UWOP_PUSH_NONVOL     (%3s, 0x%.4x)\n", tInfo->UnwindCode[j].UnwindOp, reg, tInfo->UnwindCode[j].CodeOffset);
            break;
        case UWOP_ALLOC_LARGE: // 1
            printf("0x%.2x  - UWOP_ALLOC_LARGE     (%3s, 0x%.4x)\n", tInfo->UnwindCode[j].UnwindOp, reg, tInfo->UnwindCode[j].CodeOffset);
            break;
        case UWOP_ALLOC_SMALL: // 2
            printf("0x%.2x  - UWOP_ALLOC_SMALL     (%3s, 0x%.4x)\n", tInfo->UnwindCode[j].UnwindOp, reg, tInfo->UnwindCode[j].CodeOffset);
            break;
        case UWOP_SET_FPREG: // 3
            printf("0x%.2x  - UWOP_SET_FPREG       (%3s, 0x%.4x)\n", tInfo->UnwindCode[j].UnwindOp, reg, tInfo->UnwindCode[j].CodeOffset);
            break;
        case UWOP_SAVE_NONVOL: // 4
            printf("0x%.2x  - UWOP_SAVE_NONVOL     (%3s, 0x%.4x)\n", tInfo->UnwindCode[j].UnwindOp, reg, tInfo->UnwindCode[j].CodeOffset);
            break;
        case UWOP_SAVE_NONVOL_BIG: // 5
            printf("0x%.2x  - UWOP_SAVE_NONVOL_BIG (%3s, 0x%.4x)\n", tInfo->UnwindCode[j].UnwindOp, reg, tInfo->UnwindCode[j].CodeOffset);
            break;
        case UWOP_EPILOG:            // 6
            printf("0x%.2x  - UWOP_EPILOG          (%3s, 0x%.4x)\n", tInfo->UnwindCode[j].UnwindOp, reg, tInfo->UnwindCode[j].CodeOffset);
        case UWOP_SAVE_XMM128:       // 8
            printf("0x%.2x  - UWOP_SAVE_XMM128     (%3s, 0x%.4x)\n", tInfo->UnwindCode[j].UnwindOp, reg, tInfo->UnwindCode[j].CodeOffset);
            break;
        case UWOP_SPARE_CODE:        // 7
            printf("0x%.2x  - UWOP_SPARE_CODE      (%3s, 0x%.4x)\n", tInfo->UnwindCode[j].UnwindOp, reg, tInfo->UnwindCode[j].CodeOffset);
        case UWOP_SAVE_XMM128BIG:    // 9
            printf("0x%.2x  - UWOP_SAVE_XMM128BIG  (%3s, 0x%.4x)\n", tInfo->UnwindCode[j].UnwindOp, reg, tInfo->UnwindCode[j].CodeOffset);
            break;
        case UWOP_PUSH_MACH_FRAME:
            printf("0x%.2x  - UWOP_PUSH_MACH_FRAME (%3s, 0x%.4x)\n", tInfo->UnwindCode[j].UnwindOp, reg, tInfo->UnwindCode[j].CodeOffset);
            break;
        default:
            break;
        }
        if (NULL != reg) {
            free(reg);
        }
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


PIMAGE_RUNTIME_FUNCTION_ENTRY RTFindFunctionByAddress(UINT64 moduleBase, DWORD64 functionOffset) {

    DWORD                   tSize;
    PRUNTIME_FUNCTION       pRuntimeFunctionTable;
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory;

    pRuntimeFunctionTable = (PRUNTIME_FUNCTION)(GetExceptionDirectoryAddress((HMODULE)moduleBase, &tSize));
    pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(GetExportDirectoryAddress((HMODULE)moduleBase));

    for (DWORD i = 0; i < pImageExportDirectory->NumberOfFunctions; i++)
    {
        // printf("0x%X - 0x%X\n", pRuntimeFunctionTable[i].BeginAddress, functionOffset);
        if (pRuntimeFunctionTable[i].BeginAddress == functionOffset) {

            printf("\n  Runtime Function (0x%p, 0x%p)\n  Unwind Info Address: 0x%p\n",
                (PVOID)pRuntimeFunctionTable[i].BeginAddress,
                (PVOID)pRuntimeFunctionTable[i].EndAddress,
                (PVOID)pRuntimeFunctionTable[i].UnwindInfoAddress);
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

void usage()
{
    printf("\n Unwind Inspector v%f \n", VERSION);
    printf("\n Made with <3 by %s \n\n", AUTHOR);

    printf(" Mandatory args: \n"
        "   -m <module>: Target DLL\n"
        "   -f <function>: Target Function\n"
        "   -a <function-address>: Target Function Address\n"
    );

    printf("\n\n");
}

int wmain(int argc, wchar_t** argv)
{
    LPCWSTR  moduleName                 = NULL;
    LPCWSTR  functionName               = NULL;
    UINT64   functionAddress            = NULL;
    char     functionNameA[MAX_PATH]    = {0};

    HMODULE  moduleBase                 = NULL;
    PVOID    functionPtr                = NULL;

    PERF     targetFp                   = NULL;

    while ((argc > 1) && (argv[1][0] == '-'))
    {
        switch (argv[1][1])
        {
        case 'f':
            ++argv;
            --argc;
            functionName = argv[1];
            if (wcslen(argv[1]) == 0) {
                usage();
                return -1;
            }
            break;

        case 'a':
            ++argv;
            --argc;
            if (wcslen(argv[1]) == 0) {
                usage();
                return -1;
            }
            functionAddress = (UINT64)wcstoll(argv[1], NULL, 16);
            break;

        case 'm':
            ++argv;
            --argc;
            if (wcslen(argv[1]) == 0) {
                usage();
                return -1;
            }
            moduleName = argv[1];
            break;

        case 'h':
            usage();
            return -1;
            break;

        default:
            printf("[-] Wrong Argument: %ls\n", argv[1]);
            usage();
            return -1;
        }

        ++argv;
        --argc;
    }

    if ((NULL == functionName && NULL == functionAddress) || NULL == moduleName) {
        usage();
        return -1;
    }

    moduleBase = LoadLibraryW(moduleName);
    
    if (NULL == moduleBase) {
        printf("[-] Module %ws not found. Aborting\n", moduleName);
        return -1;
    }
    
    if (NULL == functionAddress){
        size_t bytesCopied;
        wcstombs_s(&bytesCopied, (char*)functionNameA, MAX_PATH, (const wchar_t*)functionName, MAX_PATH - 1);

        functionPtr = (PVOID)GetProcAddress(moduleBase, (LPCSTR)functionNameA);
        if (NULL == functionPtr) {
            printf("[-] Function %s not found. Aborting\n", (LPCSTR)functionNameA);
            return -1;
        }
    }
    else {
        printf("[*] Using function address 0x%I64x\n", functionAddress);
        functionPtr = (PVOID)functionAddress;
    }
    
    targetFp = RTFindFunctionByAddress((UINT64)moduleBase, (DWORD64)functionPtr - (DWORD64)moduleBase);



    if (NULL == targetFp) {
        printf("[-] Function %s not found in Runtime Function Table. Aborting\n", (LPCSTR)functionNameA);
        return -1;
    }

    PrintUnwindInfo(moduleBase, (PVOID)targetFp->UnwindData);

}

