#include "pch.h"
#include <iostream>
#include <Windows.h>
#include <winternl.h> 
#include "MinHook.h"

#if _WIN64
#pragma comment(lib, "MinHook.x64.lib")
#else
#pragma comment(lib, "MinHook.x86.lib")
#endif

/* ntdll */

typedef DWORD(NTAPI* pNtAllocateVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect);

typedef DWORD(WINAPI* pNtProtectVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	PSIZE_T RegionSize,
	ULONG NewProtect,
	PULONG OldProtect);

pNtAllocateVirtualMemory pOriginalNtAllocateVirtualMemory = nullptr;
pNtProtectVirtualMemory pOriginalNtProtectVirutalMemory = nullptr;

// LdrLoadDll
typedef NTSTATUS(NTAPI* pLdrLoadDll)(PWCHAR PathToFile, ULONG Flags, PUNICODE_STRING ModuleFileName, PHANDLE ModuleHandle);
pLdrLoadDll pOriginalLdrLoadDll = nullptr;
NTSTATUS NTAPI HookedLdrLoadDll(PWCHAR PathToFile, ULONG Flags, PUNICODE_STRING ModuleFileName, PHANDLE ModuleHandle) {
	std::wcout << L"LdrLoadDll called. Loading DLL: " << ModuleFileName->Buffer << std::endl;
	return pOriginalLdrLoadDll(PathToFile, Flags, ModuleFileName, ModuleHandle);
}

// IsDebuggerPresent
typedef BOOL(WINAPI* pIsDebuggerPresent)(void);
pIsDebuggerPresent pOriginalIsDebuggerPresent = nullptr;
BOOL WINAPI HookedIsDebuggerPresent(void) {
	std::cout << "[HOOK] IsDebuggerPresent called!" << std::endl;
	return pOriginalIsDebuggerPresent();
}

// LoadLibraryA
typedef HMODULE(WINAPI* pLoadLibraryA)(LPCSTR lpLibFileName);
pLoadLibraryA pOriginalLoadLibraryA = nullptr;
HMODULE WINAPI HookedLoadLibraryA(LPCSTR lpLibFileName) {
	std::cout << "[HOOK] LoadLibraryA called with: " << lpLibFileName << std::endl;
	return pOriginalLoadLibraryA(lpLibFileName);
}

// LoadLibraryW
typedef HMODULE(WINAPI* pLoadLibraryW)(LPCWSTR lpLibFileName);
pLoadLibraryW pOriginalLoadLibraryW = nullptr;
HMODULE WINAPI HookedLoadLibraryW(LPCWSTR lpLibFileName) {
	std::wcout << L"[HOOK] LoadLibraryW called with: " << lpLibFileName << std::endl;
	return pOriginalLoadLibraryW(lpLibFileName);
}

// GetProcAddress
typedef FARPROC(WINAPI* pGetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
pGetProcAddress pOriginalGetProcAddress = nullptr;
FARPROC WINAPI HookedGetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
	std::cout << "[HOOK] GetProcAddress called for: " << lpProcName << std::endl;
	return pOriginalGetProcAddress(hModule, lpProcName);
}


DWORD NTAPI HookedNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
{
	if (Protect == PAGE_EXECUTE_READWRITE) {
		std::cout << "[HOOK] PAGE_EXECUTE_READWRITE permission detected in NtAllocateVirtualMemory function call!" << std::endl;
	}
	return pOriginalNtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

DWORD NTAPI HookedNtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect) {
	if (NewProtect == PAGE_EXECUTE_READWRITE) {
		std::cout << "[HOOK] PAGE_EXECUTE_READWRITE permission detected in NtProtectVirtualMemory function call!" << std::endl;
	}
	return pOriginalNtProtectVirutalMemory(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
}



void InitializeHooks() {
	MH_STATUS status = MH_Initialize();
	if (status != MH_OK) {
		std::cout << "Minhook init failed. Error code: " << status << std::endl;
		return;
	}

	if (MH_CreateHookApi(L"ntdll", "NtProtectVirtualMemory", &HookedNtProtectVirtualMemory, (LPVOID*)&pOriginalNtProtectVirutalMemory) != MH_OK) {
		std::cout << "Failed to hook NtProtectVirtualMemory" << std::endl;
	}

	if (MH_CreateHookApi(L"ntdll", "NtAllocateVirtualMemory", &HookedNtAllocateVirtualMemory, (LPVOID*)&pOriginalNtAllocateVirtualMemory) != MH_OK) {
		std::cout << "Failed to hook NtAllocateVirtualMemory" << std::endl;
	}

	// Hook LdrLoadDll, cause issues 
	//if (MH_CreateHookApi(L"ntdll", "LdrLoadDll", &HookedLdrLoadDll, (LPVOID*)&pOriginalLdrLoadDll) != MH_OK) {
	//	std::cout << "Could not hook LdrLoadDll" << std::endl;
	//	return;
	//}


	if (MH_CreateHookApi(L"KernelBase", "IsDebuggerPresent", &HookedIsDebuggerPresent, (LPVOID*)&pOriginalIsDebuggerPresent) != MH_OK) {
		std::cout << "Failed to hook IsDebuggerPresent" << std::endl;
		return;
	}

	/* KernelBase.dll */
	if (MH_CreateHookApi(L"KernelBase", "LoadLibraryA", &HookedLoadLibraryA, (LPVOID*)&pOriginalLoadLibraryA) != MH_OK) {
		std::cout << "Could not hook LoadLibraryA or pOriginalLoadLibraryA is NULL" << std::endl;
	}

	if (MH_CreateHookApi(L"KernelBase", "LoadLibraryW", &HookedLoadLibraryW, (LPVOID*)&pOriginalLoadLibraryW) != MH_OK) {
		std::cout << "Could not hook LoadLibraryW or pOriginalLoadLibraryW is NULL" << std::endl;
	}

	/* kernel32.dll */  // We get a loop when we hook both of them, lets look into that later
	//if (MH_CreateHookApi(L"kernel32", "LoadLibraryA", &HookedLoadLibraryA, (LPVOID*)&pOriginalLoadLibraryA) != MH_OK || pOriginalLoadLibraryA == nullptr) {
	//	std::cout << "Could not hook LoadLibraryA or pOriginalLoadLibraryA is NULL" << std::endl;
	//}

	if (MH_CreateHookApi(L"kernel32", "GetProcAddress", &HookedGetProcAddress, (LPVOID*)&pOriginalGetProcAddress) != MH_OK) {
		std::cout << "Could not hook GetProcAddress" << std::endl;
	}

	/* Setup hooks  */
	if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
		std::cout << "Failed to enable hooks." << std::endl;
		return;
	}
	std::cout << "Hooks installed successfully!" << std::endl;
}




void CreateConsole() {
	FreeConsole();

	if (AllocConsole()) {
		FILE* file;
		freopen_s(&file, "CONOUT$", "w", stdout);
		freopen_s(&file, "CONOUT$", "w", stderr);
		freopen_s(&file, "CONIN$", "w", stdin);

		SetConsoleTitle(L"Hook DLL");
		std::cout << "Console allocated..." << std::endl;
	}
}
DWORD MainFunction(LPVOID lpParam) {
	// Create a console
	CreateConsole();
	InitializeHooks();
	Sleep(500000);
	// Initialize hooks
	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		CreateThread(NULL, 0, MainFunction, NULL, 0, NULL);
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		FreeConsole();
		break;
	}
	return TRUE;
}
