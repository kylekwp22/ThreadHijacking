
#include "utils.h"
#include "shellcode.h"

DWORD GetProcessThreadID(HANDLE Process)
{
	THREADENTRY32 entry;
	entry.dwSize = sizeof(THREADENTRY32);
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	if (Thread32First(snapshot, &entry) == TRUE)
	{
		DWORD PID = GetProcessId(Process);
		while (Thread32Next(snapshot, &entry) == TRUE)
		{
			if (entry.th32OwnerProcessID == PID)
			{
				CloseHandle(snapshot);
				return entry.th32ThreadID;
			}
		}
	}
	CloseHandle(snapshot);
	return NULL;
}

void threadHijacking(HANDLE proc, const wchar_t* dllPath) {
	PMemHelper *mem = new PMemHelper();
	HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
	LPVOID loadlibrary = GetProcAddress(kernel32, "LoadLibraryW"); //addr of loadlibrary.

																   // in this case func = load dll.
																   //allocating space in memory for path and shellcode
	int pathLength = wcslen(dllPath) + 1;
	int path_plus_shell = pathLength + sizeof(shellcode);
	LPVOID stringMem = VirtualAllocEx(proc, NULL, path_plus_shell, MEM_COMMIT, PAGE_EXECUTE);
	LPVOID shellCodeMem = (LPVOID)((DWORD)stringMem + pathLength);
	/*
	we got spaces for path + shellcode
	*/

	// we want to get process Thread ID as well

	// suspend the thread and query its control context
	DWORD threadID = GetProcessThreadID(proc);

	if (!threadID)
	{
		printf("\nError: Unable to open target thread handle (%d)\n", GetLastError());

		VirtualFreeEx(proc, mem, 0, MEM_RELEASE);
		CloseHandle(proc);
		return;
	}

	// setting thread specific access rights
	//THREAD_SUSPEND_RESUME for suspension of thread
	//THREAD_GET_CONTEXT : Required to read the context of a thread using GetThreadContext. // MSDN
	//THREAD_SET_CONTEXT : Required to write the context of a thread using SetThreadContext. // MSDN
	HANDLE thread = OpenThread((THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT), false, threadID);
	SuspendThread(thread);
	printf("Suspending Thread");
	//not that the thread is suspended, we can extract thread context information
	CONTEXT threadContext;
	threadContext.ContextFlags = CONTEXT_CONTROL; // // SS:SP, CS:IP, FLAGS, BP
	GetThreadContext(thread, &threadContext); //2nd arg to extract context info

											  //shellcode modification
	memcpy(&shellcode[65], &stringMem, 0x8); //PUSH &stringMem
	memcpy(&shellcode[55], &loadlibrary, 0x8); // MOV EAX, &LoadLibrary
	memcpy(&shellcode[121], &threadContext.Rip, 0x8); //Eip -> Rip if compiling for 64bit

	
												   //code caving
												   
	//WriteProcessMemory(proc, stringMem, dllPath, pathLength, NULL);
	//WriteProcessMemory(proc, shellCodeMem, shellcode, sizeof(shellcode), NULL);
	mem->WriteVirtual(cr3, (uint64_t)stringMem, (LPVOID)dllPath, sizeof(dllPath));
	mem->WriteVirtual(cr3, (uint64_t)shellCodeMem, (LPVOID)shellcode, sizeof(shellcode));
	printf("ShellCode Injected");
	//hijacking the thread, set EIp (RIP) to shellcode
	threadContext.Rip = (DWORD)shellCodeMem;
	threadContext.ContextFlags = CONTEXT_CONTROL;
	SetThreadContext(thread, &threadContext);

	//as if nothing hapnned
	ResumeThread(thread);
	CloseHandle(thread);

}