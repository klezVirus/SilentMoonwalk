// dllmain.cpp : Defines the entry point for the DLL application.
#include <process.h>
#include <iostream>
#include <Windows.h>
#include <dbghelp.h>
#include <tlhelp32.h>
#include <string>
#include <psapi.h>
#include <tchar.h>
#include "Performance.h"
#pragma comment(lib, "dbghelp.lib")

#include "hde64.h"
typedef hde64s HDE;

#ifdef _DEBUG
#define DPRINT(...) { printf(__VA_ARGS__); }
#else
#define DPRINT(...) {}
#endif

int LoadPrivilege(void) {
	HANDLE hToken;
	LUID Value;
	TOKEN_PRIVILEGES tp;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return(GetLastError());
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &Value))
		return(GetLastError());
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = Value;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL))
		return(GetLastError());
	CloseHandle(hToken);
	return 1;
}

bool check_number(std::string str) {
	for (int i = 0; i < str.length(); i++)
		if (isdigit(str[i]) == false)
			return false;
	return true;
}

#define DBGHELP_TRANSLATE_TCHAR
void Analyze(int pid)
{
	DWORD nAlerts = 0;
	TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");
	CONTEXT context = { 0 };
	context.ContextFlags = CONTEXT_FULL;

	//const HANDLE hProcess = ::GetCurrentProcess();
	HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
	if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE) {
		hProcess = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
		if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE) {
			printf("[X] Can't get handle to process.\n");
			return;
		}
	}
	DPRINT("[Information] Analyzing PID: %d\n", pid);
	HMODULE hMod;
	DWORD cbNeeded;

	hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	//DWORD pid = GetProcessId(hProcess);
	//DPRINT("ERROR OpenProcess: %d\n", GetLastError());
	//const HANDLE hThread = ::GetCurrentThread();
	//const HANDLE hThread = ::OpenThread(THREAD_ALL_ACCESS, FALSE, 16780);
	//DPRINT("ERROR OpenThread: %d\n", GetLastError());

	if (hProcess == NULL) {
		DPRINT("[X] Can't get handle to process.  Check that PID exists and that you have proper permissions.\n");
		return;
	}

	if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded))
	{
		GetModuleBaseName(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(TCHAR));
	}

	hMod = NULL;
	cbNeeded = NULL;

	HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (h != INVALID_HANDLE_VALUE)
	{
		THREADENTRY32 te;
		te.dwSize = sizeof(te);
		if (Thread32First(h, &te))
		{
			do
			{
				if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(te.th32OwnerProcessID))
				{
					// Suspend all threads EXCEPT the one we want to keep running
					if (te.th32OwnerProcessID == pid)
					{
						HANDLE hThread = ::OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
						DPRINT("Analyzing ThreadID: %d\n", te.th32ThreadID);
						if (hThread == NULL) {
							DPRINT("[X] Can't get handle to thread.  Check that you have proper permissions.\n");
							exit(0);
						}

						SuspendThread(hThread);
						GetThreadContext(hThread, &context);
						ResumeThread(hThread);

						STACKFRAME64 stack = { 0 };
						stack.AddrPC.Offset = context.Rip;
						stack.AddrPC.Mode = AddrModeFlat;
						stack.AddrStack.Offset = context.Rsp;
						stack.AddrStack.Mode = AddrModeFlat;
						stack.AddrFrame.Offset = context.Rsp;
						stack.AddrFrame.Mode = AddrModeFlat;

						SymInitialize(hProcess, NULL, TRUE);
						SymSetOptions(SYMOPT_LOAD_LINES);

						SYMBOL_INFO* pSymbol = (SYMBOL_INFO*)calloc(sizeof(SYMBOL_INFO) + sizeof(TCHAR) * 255, 1);

						//std::string last_funcname;
						//last_funcname = pSymbol->Name;
						//std::string stack_trace;
						for (int frame = 0; ; ++frame)
						{
							BOOL result = StackWalk64(IMAGE_FILE_MACHINE_AMD64, hProcess, hThread, &stack, &context, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL);

							pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
							pSymbol->MaxNameLen = 256;

							DWORD64 displacement;
							SymFromAddr(hProcess, stack.AddrPC.Offset, &displacement, pSymbol);

							if (!result) {
								break;
							}
							else {
								// Resolve the return address of the function
								// Once resolving the return address, use HDE/Hacker Disassembly engine to go back 1 instruciton
								// Check if instruction is a call
								// If instruction is a call, validate it is a call to last_funcname by resolving name based on address
								// If instruction is not a call, alert
								// If the callstack doesnt contain the called function, alert
								// Alert on RtlUserThreadStart HAVING a return address
							}

							//if (!stack_trace.empty()) stack_trace.append(1, L'\n');
							//stack_trace.append(pSymbol->Name);
							//DPRINT("Analyzing Function Frame: %s\n PC Address: 0x%p\n Stack Address: 0x%p\n Return Address: 0x%p\n", pSymbol->Name, (ULONG64)stack.AddrPC.Offset, (ULONG64)stack.AddrStack.Offset, (ULONG64)stack.AddrReturn.Offset);

							if ((LPVOID)stack.AddrReturn.Offset != 0) {
								int valid = 0;
								SIZE_T read = 0;
								void* bytes = malloc(64);
								ReadProcessMemory(hProcess, (LPBYTE)stack.AddrReturn.Offset - 0x20, bytes, 64, &read);
								LPVOID baseLoc = (LPVOID)((LPBYTE)bytes + 0x20);
								LPBYTE Validate = (LPBYTE)baseLoc;

								HDE hs;
								HDE hsLongCall;
								HDE hsShortCall;
								HDE hsRelativeCallShort;
								HDE hsCallRegister;
								HDE hsRelativeCall;
								HDE hsSyscall;
								hde64_disasm(Validate - 0x07, &hsLongCall); // 48 FF MODR/M Rex.W 1
								hde64_disasm(Validate - 0x06, &hsShortCall); // FF MODR/M Rex.W 0
								hde64_disasm(Validate - 0x03, &hsRelativeCallShort); // FF 2 BYTES ADDRESS
								hde64_disasm(Validate - 0x02, &hsCallRegister); // FF Call to register
								hde64_disasm(Validate - 0x05, &hsRelativeCall); // E8 4 BYTES ADDRESS
								hde64_disasm(Validate - 0x02, &hsSyscall); // 0F05 Syscall
								hde64_disasm(Validate, &hs); // Opcode at return address

								if (hsLongCall.opcode != 0xff && hsShortCall.opcode != 0xff && hsRelativeCallShort.opcode != 0xff && hsCallRegister.opcode != 0xff && hsRelativeCall.opcode != 0xE8 && hsSyscall.opcode != 0x0f) { // Observed functions causing FP's
									DPRINT("\nAnalyzed Function Frame: %s\n PC Address: 0x%p\n Stack Address: 0x%p\n Return Address: 0x%p\n", pSymbol->Name, (ULONG64)stack.AddrPC.Offset, (ULONG64)stack.AddrStack.Offset, (ULONG64)stack.AddrReturn.Offset);
									DPRINT("[X] Possibly spoofed return address observed!  There is a false caller observed here.\n");
									DPRINT("[!] This alert was generated because a call was not observed before the return address, therefore it is incredibly unlikely that this return address is valid.\n UNLESS this is a JIT process (such as a C Sharp Process).  Then FP's are expected.\n");
									DPRINT("[Information] Opcode observed at return address is: 0x%02X\n", hs.opcode);

									//_tprintf(TEXT("[!][%s] Potentially tampered return address. Reason (0x%02X) opcode identified as return address\n"), szProcessName, hs.opcode);
									//_tprintf(TEXT("[!][%s] Function Frame: %s\n PC Address: 0x%p\n Stack Address: 0x%p\n Return Address: 0x%p\n"), szProcessName, pSymbol->Name, (ULONG64)stack.AddrPC.Offset, (ULONG64)stack.AddrStack.Offset, (ULONG64)stack.AddrReturn.Offset);
									nAlerts++;
									if (hs.opcode == 0xff) {
										DPRINT("[Information] Opcode argument observed at return address is: 0x%02X\n", Validate[1]);
										if (hs.opcode == 0xff) {
											DPRINT("[!] 0xFF Instruction found.  This opcode is generally used for performing calls and jumps.  Investigate the argument in a utility like https://defuse.ca/online-x86-assembler.htm and trace the jmp to observe the real caller.\n");
										}
									}
								}


								free(bytes);
							}

							// RtlUserThreadStart has a return address of 0.  Where would it return to!
							if ((LPVOID)stack.AddrReturn.Offset != 0 && strcmp(pSymbol->Name, "RtlUserThreadStart") == 0) {
								DPRINT("This is an alert for an invalid RtlUserThreadStart return address.  RtluserThreadStart should never contain a return address.\n");
								// printf("[!][%s] Tampered RtlUserThreadStart Address", szProcessName);
								nAlerts++;
							}

							//DPRINT("Last function called is: %s\n", last_funcname.c_str());
							/*if ((LPVOID)stack.AddrReturn.Offset != 0) {
								SIZE_T read = 0;
								void* bytes = malloc(10);
								ReadProcessMemory(hProcess, (LPBYTE)stack.AddrReturn.Offset-0x07, bytes, 10, &read);
								LPBYTE Validate = (LPBYTE)bytes + 0x07;
								Validate = Validate - 0x05;
								HDE hs;
								hde64_disasm(Validate, &hs);

								// Turn this into a case statement using like bytes[7]
								if (hs.opcode == 0xE8) {
									// Regular call, E8 with relative 4 byte address after
									//DPRINT("Opcode is 0x%02X\n", hs.opcode);
									//DPRINT("Regular relative call.\n\n");
									//DPRINT("[Information] Opcode observed is: 0x%02X\n", hs.opcode);
									//DPRINT("[Information] Valid relative call instruction found.\n");
								}
								else {
									//DPRINT("[Information] Opcode observed at -0x05 was: 0x%02X\n", hs.opcode);
									// Long Call QORD PTR, REX.W is 1 (or 48 hex) FF Opcode then MODR/M
									Validate = Validate - 0x02;
									hs = { 0 };
									hde64_disasm(Validate, &hs);
									if (hs.opcode == 0xff && hs.rex_w == 1) {
										//DPRINT("Opcode is 0x%02X\n", hs.opcode);
										//DPRINT("rex_w is 0x%02X\n", hs.rex_w);
										//DPRINT("Long call.\n\n");
										//DPRINT("[Information] Opcode observed is: 0x%02X\n", hs.opcode);
										//DPRINT("[Information] rex_w observed is: 0x%02X\n", hs.rex_w);
										//DPRINT("[Information] Valid long call qword ptr instruction found.\n");
									}
									else {
										//DPRINT("[Information] Opcode observed at -0x07 was: 0x%02X\n", hs.opcode);
										// Short Call QWORD PTR, 2 bytes, FF Opcode then MODR/M
										Validate = Validate + 0x1;
										hs = { 0 };
										hde64_disasm(Validate, &hs);
										if (hs.opcode == 0xff && hs.rex_w == 0) {
											//DPRINT("Opcode is 0x%02X\n", hs.opcode);
											//DPRINT("rex_w is 0x%02X\n", hs.rex_w);
											//DPRINT("Short call.\n\n");
											//DPRINT("[Information] Opcode observed is: 0x%02X\n", hs.opcode);
											//DPRINT("[Information] Valid short call qword ptr instruction found.\n");
										}
										else {
											//DPRINT("[Information] Opcode observed at -0x06 was: 0x%02X\n", hs.opcode);
											Validate = Validate + 0x4;
											hs = { 0 };
											hde64_disasm(Validate, &hs);
											if (hs.opcode == 0xff) {
												//DPRINT("[Information] Opcode observed is: 0x%02X\n", hs.opcode);
												//DPRINT("[Information] Valid call/jmp opcode found.\n");
											}
											else if (hs.opcode == 0x0f && hs.opcode2 == 0x05) {
												//DPRINT("[Information] Opcode observed is: 0x%02X%02X\n", hs.opcode, hs.opcode2);
												//DPRINT("[Information] Valid syscall opcode found.\n");
											}
											else {
												DPRINT("Analyzed Function Frame: %s\n PC Address: 0x%p\n Stack Address: 0x%p\n Return Address: 0x%p\n", pSymbol->Name, (ULONG64)stack.AddrPC.Offset, (ULONG64)stack.AddrStack.Offset, (ULONG64)stack.AddrReturn.Offset);
												DPRINT("[X] Spoofed return address observed!  There is a false caller observed here.\n");
												DPRINT("[!] This alert was generated because a call was not observed before the return address, therefore it is incredibly unlikely that this return address is valid.\n");

												Validate = Validate + 0x02;
												hs = { 0 };
												hde64_disasm(Validate, &hs);
												DPRINT("[Information] Opcode observed at return address is: 0x%02X\n", hs.opcode);

												if (hs.opcode != Validate[1] && hs.opcode == 0xff) {
													DPRINT("[Information] Opcode argument observed at return address is: 0x%02X\n", Validate[1]);
													if (hs.opcode == 0xff) {
														DPRINT("[!] 0xFF Instruction found.  This opcode is generally used for performing calls and jumps.  Investigate the argument in a utility like https://defuse.ca/online-x86-assembler.htm and trace the jmp to observe the real caller.\n\n");
													}
												}
												else {
													DPRINT("\n");
												}
											}
										}
									}
								}
								free(bytes);
							}*/
						}

						free(pSymbol);

						//DPRINT("%s", stack_trace.c_str());
					}
				}
				te.dwSize = sizeof(te);
			} while (Thread32Next(h, &te));
		}
		CloseHandle(h);
	}
	if (NULL != hProcess) {
		CloseHandle(hProcess);
	}
	if(nAlerts > 0){
		_tprintf(TEXT("[!][%s] Suspicious return address. Alerts: (%u)\n"), szProcessName, nAlerts);
	}
	else {
		_tprintf(TEXT("[+][%s] CLEAN!\n"), szProcessName);
	}
	return;
}


int main(int argc, char* argv[]) {

	LARGE_INTEGER timer = ::timer();

	int nAlerts = 0;
	int ObtainedDebug = LoadPrivilege();
	if (ObtainedDebug != 1) {
		DPRINT("[X] Failed to get debug privileges, can only handle owned procs.\n");
	}

	if (argc >= 2) {
		std::string pidS = argv[1];
		if (check_number(pidS) != true) {
			DPRINT("[X] Must provide an integer as a pid.");
			exit(0);
		}
		DWORD pid = atoi(argv[1]);
		Analyze(pid);
	}else{
		DWORD aProcesses[1024], cbNeeded, cProcesses;
		unsigned int i;

		if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
		{
			return 1;
		}

		cProcesses = cbNeeded / sizeof(DWORD);
		for (i = 0; i < cProcesses; i++)
		{
			if (aProcesses[i] != 0)
			{
				DPRINT("[*] Analyzing PID: %u\n", aProcesses[i]);
				Analyze(aProcesses[i]);
			}
		}
		elapsed_time(timer);

	}

	return 0;
}