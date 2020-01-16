/*
	Copyright (c) 2019 Rat431 (https://github.com/Rat431).
	This software is under the MIT license, for more informations check the LICENSE file.
*/

#include "ColdMDLoader.h"

// Custom MACROs
#define RLC_FLAG64b(Data) ((Data >> 12) == IMAGE_REL_BASED_DIR64)
#define RLC_FLAG32b(Data) ((Data >> 12) == IMAGE_REL_BASED_HIGHLOW)
#ifdef _WIN64
#define RLC_FLAG RLC_FLAG64b
#define VALID_MACHINE IMAGE_FILE_MACHINE_AMD64
#else
#define RLC_FLAG RLC_FLAG32b
#define VALID_MACHINE IMAGE_FILE_MACHINE_I386
#endif

// For the remote code
typedef HMODULE(WINAPI* __LoadLibA__)(LPCSTR);
typedef HMODULE(WINAPI* __LoadLibExA__)(LPCSTR, HANDLE, DWORD);
typedef FARPROC(WINAPI* __GetProcAddress__)(HMODULE, LPCSTR);
typedef BOOL(APIENTRY* __DllMain__)(HMODULE, DWORD, LPVOID);
typedef BOOL(WINAPI* __FreeLibrary__)(HMODULE);

struct InjectionRC_Info
{
	int32_t LFlag;
	int32_t Signal;

	void* BaseAddr;
	char* LibraryN;
	IMAGE_NT_HEADERS* pNt;

	__GetProcAddress__ __GetProcAddress;
	__LoadLibExA__ __LoadLibExA;
	__LoadLibA__ __LoadLibA;
	__FreeLibrary__ __FreeLibrary;
};
namespace CMDLoader_Vars
{
	bool Inited = false;
	int32_t CurrentID = 0;
	std::multimap<int32_t, ModuleMap_Info> RegisteredModules;
	std::mutex Thread;
}
namespace CMDLoader_Service_Private
{
	// This function will run in the remote process
	void REMOTECODEF RemoteInjector(InjectionRC_Info* InjectionData)
	{
		if (InjectionData) {
			if (InjectionData->LFlag == MANUAL_INJECTION) {
				// Declare some variables
				__LoadLibA__ LoadLibraryFA = InjectionData->__LoadLibA;
				__GetProcAddress__ GetProcAddr = InjectionData->__GetProcAddress;

				// Let's start doing relocations
				DWORD_PTR Delta = (DWORD_PTR)InjectionData->BaseAddr - InjectionData->pNt->OptionalHeader.ImageBase;

				// If the difference is 0, the allocated base address as the image base, so we don't need to fix relocations.
				if (Delta != NULL) {
					// Check if there are relocations to fix
					if (InjectionData->pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0) {
						IMAGE_BASE_RELOCATION* pBaseRelocation = (IMAGE_BASE_RELOCATION*)((ULONG_PTR)InjectionData->BaseAddr + InjectionData->pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
						while (pBaseRelocation->VirtualAddress) {
							if (pBaseRelocation->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
								UINT CountRelocs = (pBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
								WORD* list = (WORD*)(pBaseRelocation + 1);

								for (UINT i = 0; i < CountRelocs; i++, list++) {
									// Check if the bits contains the right flags
									if (RLC_FLAG(*list)) {
										DWORD_PTR* PatchData = (DWORD_PTR*)((DWORD_PTR)InjectionData->BaseAddr + pBaseRelocation->VirtualAddress + (*list & 0xFFF));
										if (PatchData) {
											*PatchData += Delta;
										}
										else {
											InjectionData->Signal = FALIED_INJECTION;
											return;
										}
									}
								}
							}
							pBaseRelocation = (IMAGE_BASE_RELOCATION*)((ULONG_PTR)pBaseRelocation + pBaseRelocation->SizeOfBlock);
						}
					}
				}
				// IAT now
				if (InjectionData->pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0) {
					IMAGE_IMPORT_DESCRIPTOR* pImportD = (IMAGE_IMPORT_DESCRIPTOR*)((ULONG_PTR)InjectionData->BaseAddr + InjectionData->pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
					while (pImportD->Characteristics && pImportD->Name) {
						// Load the library
						auto pName = (LPSTR)((ULONG_PTR)InjectionData->BaseAddr + pImportD->Name);
						HMODULE hLib = LoadLibraryFA(pName);

						if (hLib) {
							IMAGE_THUNK_DATA* pThunk = (IMAGE_THUNK_DATA*)((ULONG_PTR)InjectionData->BaseAddr + pImportD->FirstThunk);
							IMAGE_THUNK_DATA* pOrigThunk = (IMAGE_THUNK_DATA*)((ULONG_PTR)InjectionData->BaseAddr + pImportD->OriginalFirstThunk);
							while (pOrigThunk->u1.AddressOfData) {
								if (pOrigThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
									ULONG_PTR FunctionL = (ULONG_PTR)GetProcAddr(hLib, (LPSTR)IMAGE_ORDINAL(pOrigThunk->u1.Ordinal));
									pThunk->u1.Function = FunctionL;
								}
								else {
									IMAGE_IMPORT_BY_NAME* pNameImport = (IMAGE_IMPORT_BY_NAME*)((ULONG_PTR)InjectionData->BaseAddr + pOrigThunk->u1.AddressOfData);
									ULONG_PTR FunctionL = (ULONG_PTR)GetProcAddr(hLib, (LPSTR)pNameImport->Name);
									pThunk->u1.Function = FunctionL;
								}
								pThunk++;
								pOrigThunk++;
							}
						}
						pImportD++;
					}
				}

				// TLS Callbacks
				if (InjectionData->pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size > 0) {
					IMAGE_TLS_DIRECTORY* pTLSDir = (IMAGE_TLS_DIRECTORY*)((ULONG_PTR)InjectionData->BaseAddr + InjectionData->pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
					PIMAGE_TLS_CALLBACK Call = nullptr;
					void** Callback = nullptr;
					Callback = (void**)pTLSDir->AddressOfCallBacks;
					while (Callback && *Callback) {
						Call = (PIMAGE_TLS_CALLBACK)*Callback;
						Call(InjectionData->BaseAddr, DLL_PROCESS_ATTACH, NULL);
						Callback++;
					}
				}

				// Entry point
				if (InjectionData->pNt->OptionalHeader.AddressOfEntryPoint) {
					__DllMain__ Main = (__DllMain__)((ULONG_PTR)InjectionData->BaseAddr + InjectionData->pNt->OptionalHeader.AddressOfEntryPoint);
					Main((HMODULE)InjectionData->BaseAddr, DLL_PROCESS_ATTACH, NULL);
				}
				InjectionData->Signal = SUCCESS_RETURNED;
			}
			else if (InjectionData->LFlag == STANDARD_INJECTION) {
				// Declare some variables
				__LoadLibExA__ LoadLibraryExFA = InjectionData->__LoadLibExA;
				HMODULE Module;

				// Load the module 
				Module = LoadLibraryExFA(InjectionData->LibraryN, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
				if (!Module) {
					InjectionData->Signal = FALIED_MODULE_LOAD;
				}
				else {
					InjectionData->Signal = SUCCESS_RETURNED;
					InjectionData->BaseAddr = (void*)Module;
				}
			}
			else {
				InjectionData->Signal = FALIED_INJECTION;
			}
		}
		else {
			InjectionData->Signal = FALIED_INJECTION;
		}
	}
	bool IsProcessSameArch(HANDLE hProcess, void* MainModuleBase, int32_t* OutErrorCode)
	{
		IMAGE_DOS_HEADER Dos = { 0 };
		IMAGE_NT_HEADERS Nt = { 0 };
		SIZE_T ReadData;

		if (!ReadProcessMemory(hProcess, MainModuleBase, &Dos, sizeof(IMAGE_DOS_HEADER), &ReadData)) {
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_READING_PROCESS_MEM;
			}
			return false;
		}
		if (!ReadProcessMemory(hProcess, (void*)((ULONG_PTR)MainModuleBase + Dos.e_lfanew), &Nt, sizeof(IMAGE_NT_HEADERS), &ReadData)) {
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_READING_PROCESS_MEM;
			}
			return false;
		}
		if (Nt.FileHeader.Machine != VALID_MACHINE) {
			if (OutErrorCode > NULL) {
				*OutErrorCode = NULL;
			}
			return false;
		}
		if (OutErrorCode > NULL) {
			*OutErrorCode = NULL;
		}
		return true;
	}
}

namespace CMDLoader_Service
{
	// Mapping functions 
	int32_t InitModuleInjection(HANDLE hProcess, const char* DllFileName, int32_t LFlag, ModuleMap_Info* OutMapInfo, int32_t* OutErrorCode)
	{
		// Paramaters first checks 
		if (hProcess == INVALID_HANDLE_VALUE) {
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_INVALID_PARAMETER;
			}
			return NULL;
		}
		if (!DllFileName) {
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_INVALID_PARAMETER;
			}
			return NULL;
		}
		if (!OutMapInfo) {
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_INVALID_PARAMETER;
			}
			return NULL;
		}

		// Check if the service is started
		if (!CMDLoader_Vars::Inited) {
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_NEEDS_INITIALIZATION;
			}
			return NULL;
		}

		// Thread safe 
		CMDLoader_Vars::Thread.lock();

		// For the remote code
		InjectionRC_Info InjectionStructure;
		LPVOID PageRemoteCodeLoader = VirtualAllocEx(hProcess, NULL, 0x7000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		LPVOID PageRemoteCodeStructure = VirtualAllocEx(hProcess, NULL, sizeof(InjectionRC_Info), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		if (!PageRemoteCodeLoader) {
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_MEM_ALLOCATION;
			}
			CMDLoader_Vars::Thread.unlock();
			return NULL;
		}
		if (!PageRemoteCodeStructure) {
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_MEM_ALLOCATION;
			}
			VirtualFreeEx(hProcess, PageRemoteCodeLoader, NULL, MEM_RELEASE);
			CMDLoader_Vars::Thread.unlock();
			return NULL;
		}

		// Check which type of injection should be performed.
		if (LFlag == STANDARD_INJECTION)
		{
			// Declare variables 
			HANDLE RemoteThread;
			LPVOID PageString;
			SIZE_T LString;

			// Start by getting the length of the requested module file string 
			LString = lstrlenA(DllFileName);

			// Allocate to the target process a page which will be used to store our module file name.
			PageString = VirtualAllocEx(hProcess, NULL, LString + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			if (PageString == NULL) {
				if (OutErrorCode > NULL) {
					*OutErrorCode = FALIED_MEM_ALLOCATION;
				}
				VirtualFreeEx(hProcess, PageRemoteCodeLoader, NULL, MEM_RELEASE);
				VirtualFreeEx(hProcess, PageRemoteCodeStructure, NULL, MEM_RELEASE);
				CMDLoader_Vars::Thread.unlock();
				return NULL;
			}

			// Copy the string
			if (!WriteProcessMemory(hProcess, PageString, DllFileName, LString, NULL)) {
				if (OutErrorCode > NULL) {
					*OutErrorCode = FALIED_INJECTION;
				}
				VirtualFreeEx(hProcess, PageRemoteCodeLoader, NULL, MEM_RELEASE);
				VirtualFreeEx(hProcess, PageRemoteCodeStructure, NULL, MEM_RELEASE);
				VirtualFreeEx(hProcess, PageString, NULL, MEM_RELEASE);
				CMDLoader_Vars::Thread.unlock();
				return NULL;
			}
			InjectionStructure.LFlag = STANDARD_INJECTION;

			InjectionStructure.LibraryN = (char*)PageString;
			InjectionStructure.BaseAddr = nullptr;
			InjectionStructure.pNt = nullptr;

			InjectionStructure.__LoadLibExA = (__LoadLibExA__)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryExA");
			InjectionStructure.__FreeLibrary = NULL;
			InjectionStructure.__GetProcAddress = NULL;
			InjectionStructure.__LoadLibA = NULL;

			InjectionStructure.Signal = 0;

			// Copy the filled structure
			if (!WriteProcessMemory(hProcess, PageRemoteCodeStructure, &InjectionStructure, sizeof(InjectionRC_Info), NULL)) {
				if (OutErrorCode > NULL) {
					*OutErrorCode = FALIED_INJECTION;
				}
				VirtualFreeEx(hProcess, PageRemoteCodeLoader, NULL, MEM_RELEASE);
				VirtualFreeEx(hProcess, PageRemoteCodeStructure, NULL, MEM_RELEASE);
				VirtualFreeEx(hProcess, PageString, NULL, MEM_RELEASE);
				CMDLoader_Vars::Thread.unlock();
				return NULL;
			}

			if (!WriteProcessMemory(hProcess, PageRemoteCodeLoader, CMDLoader_Service_Private::RemoteInjector, 0x7000, NULL)) {
				if (OutErrorCode > NULL) {
					*OutErrorCode = FALIED_INJECTION;
				}
				VirtualFreeEx(hProcess, PageRemoteCodeLoader, NULL, MEM_RELEASE);
				VirtualFreeEx(hProcess, PageRemoteCodeStructure, NULL, MEM_RELEASE);
				VirtualFreeEx(hProcess, PageString, NULL, MEM_RELEASE);
				CMDLoader_Vars::Thread.unlock();
				return NULL;
			}

			RemoteThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)PageRemoteCodeLoader, PageRemoteCodeStructure, 0, NULL);
			if (RemoteThread == NULL) {
				if (OutErrorCode > NULL) {
					*OutErrorCode = FALIED_REMOTE_THREAD_CREATION;
				}
				VirtualFreeEx(hProcess, PageRemoteCodeLoader, NULL, MEM_RELEASE);
				VirtualFreeEx(hProcess, PageRemoteCodeStructure, NULL, MEM_RELEASE);
				VirtualFreeEx(hProcess, PageString, NULL, MEM_RELEASE);
				CMDLoader_Vars::Thread.unlock();
				return NULL;
			}

			// Wait for the finished signal 
			while (InjectionStructure.Signal == 0)
			{
				if (!ReadProcessMemory(hProcess, PageRemoteCodeStructure, &InjectionStructure, sizeof(InjectionRC_Info), NULL)) {
					InjectionStructure.Signal = WARN_NO_RETURN_SIGNAL;
					break;
				}
				// Sleep for 1 second and try again 
				Sleep(1000);
			}

			if (OutErrorCode > NULL) {
				*OutErrorCode = InjectionStructure.Signal;
			}

			// Wait the thread for finish 
			WaitForSingleObject(RemoteThread, INFINITE);

			if (InjectionStructure.Signal == SUCCESS_RETURNED) {

				// Fill the informations struct
				OutMapInfo->StatusLoaded = true;
				OutMapInfo->PID = GetProcessId(hProcess);
				OutMapInfo->MBaseAddress = InjectionStructure.BaseAddr;
				OutMapInfo->LFlag = STANDARD_INJECTION;

				VirtualFreeEx(hProcess, PageRemoteCodeLoader, NULL, MEM_RELEASE);
				VirtualFreeEx(hProcess, PageRemoteCodeStructure, NULL, MEM_RELEASE);
				VirtualFreeEx(hProcess, PageString, NULL, MEM_RELEASE);

				CMDLoader_Vars::CurrentID++;
				CMDLoader_Vars::Thread.unlock();
				return CMDLoader_Vars::CurrentID;
			}
			VirtualFreeEx(hProcess, PageRemoteCodeLoader, NULL, MEM_RELEASE);
			VirtualFreeEx(hProcess, PageRemoteCodeStructure, NULL, MEM_RELEASE);
			VirtualFreeEx(hProcess, PageString, NULL, MEM_RELEASE);
			CMDLoader_Vars::Thread.unlock();
			return NULL;
		}
		else if (LFlag == MANUAL_INJECTION)
		{
			// Declare variables
			HANDLE RemoteThread;
			HANDLE FileHandle;

			LPVOID PEHeader = NULL;
			LPVOID FileBData;

			DWORD tmp;
			SIZE_T FileSize;
			
			IMAGE_DOS_HEADER* pDosHeader = NULL;
			IMAGE_NT_HEADERS* pNtHeader = NULL;
			IMAGE_SECTION_HEADER* pSecHeader = NULL;

			// Start by creating a new handle to the requested file.
			FileHandle = CreateFileA(DllFileName, GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (FileHandle == INVALID_HANDLE_VALUE) {
				if (OutErrorCode > NULL) {
					*OutErrorCode = FALIED_FILE_HANDLE_INVALID;
				}
				VirtualFreeEx(hProcess, PageRemoteCodeLoader, NULL, MEM_RELEASE);
				VirtualFreeEx(hProcess, PageRemoteCodeStructure, NULL, MEM_RELEASE);
				CMDLoader_Vars::Thread.unlock();
				return NULL;
			}
			FileSize = GetFileSize(FileHandle, NULL);
			if (FileSize < 0x1000) {
				if (OutErrorCode > NULL) {
					*OutErrorCode = FALIED_INVALID_PE;
				}
				CloseHandle(FileHandle);
				VirtualFreeEx(hProcess, PageRemoteCodeLoader, NULL, MEM_RELEASE);
				VirtualFreeEx(hProcess, PageRemoteCodeStructure, NULL, MEM_RELEASE);
				CMDLoader_Vars::Thread.unlock();
				return NULL;
			}
			FileBData = VirtualAlloc(NULL, FileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			if (FileBData == NULL) {
				if (OutErrorCode > NULL) {
					*OutErrorCode = FALIED_ALLOCATION;
				}
				CloseHandle(FileHandle);
				VirtualFreeEx(hProcess, PageRemoteCodeLoader, NULL, MEM_RELEASE);
				VirtualFreeEx(hProcess, PageRemoteCodeStructure, NULL, MEM_RELEASE);
				CMDLoader_Vars::Thread.unlock();
				return NULL;
			}

			// Read the file bytes.
			if (!ReadFile(FileHandle, FileBData, FileSize, &tmp, NULL)) {
				if (OutErrorCode > NULL) {
					*OutErrorCode = FALIED_FILE_READ;
				}
				CloseHandle(FileHandle);
				VirtualFree(FileBData, NULL, MEM_RELEASE);
				VirtualFreeEx(hProcess, PageRemoteCodeLoader, NULL, MEM_RELEASE);
				VirtualFreeEx(hProcess, PageRemoteCodeStructure, NULL, MEM_RELEASE);
				CMDLoader_Vars::Thread.unlock();
				return NULL;
			}

			// Read headers now
			pDosHeader = (IMAGE_DOS_HEADER*)FileBData;
			if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
				if (OutErrorCode > NULL) {
					*OutErrorCode = FALIED_INVALID_PE;
				}
				CloseHandle(FileHandle);
				VirtualFree(FileBData, NULL, MEM_RELEASE);
				VirtualFreeEx(hProcess, PageRemoteCodeLoader, NULL, MEM_RELEASE);
				VirtualFreeEx(hProcess, PageRemoteCodeStructure, NULL, MEM_RELEASE);
				CMDLoader_Vars::Thread.unlock();
				return NULL;
			}
			pNtHeader = (IMAGE_NT_HEADERS*)((ULONG_PTR)FileBData + pDosHeader->e_lfanew);
			if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
				if (OutErrorCode > NULL) {
					*OutErrorCode = FALIED_INVALID_PE;
				}
				CloseHandle(FileHandle);
				VirtualFree(FileBData, NULL, MEM_RELEASE);
				VirtualFreeEx(hProcess, PageRemoteCodeLoader, NULL, MEM_RELEASE);
				VirtualFreeEx(hProcess, PageRemoteCodeStructure, NULL, MEM_RELEASE);
				CMDLoader_Vars::Thread.unlock();
				return NULL;
			}
			if (pNtHeader->FileHeader.Machine != VALID_MACHINE) {
				if (OutErrorCode > NULL) {
					*OutErrorCode = FALIED_INVALID_PE_ARCH;
				}
				CloseHandle(FileHandle);
				VirtualFree(FileBData, NULL, MEM_RELEASE);
				VirtualFreeEx(hProcess, PageRemoteCodeLoader, NULL, MEM_RELEASE);
				VirtualFreeEx(hProcess, PageRemoteCodeStructure, NULL, MEM_RELEASE);
				CMDLoader_Vars::Thread.unlock();
				return NULL;
			}

			// Allocate a new buffer to the target process which will be used for the remote module.
			// We firstly try to allocate a page with the same base address as the target image base to avoid to fix relocations
			PEHeader = VirtualAllocEx(hProcess, (LPVOID)pNtHeader->OptionalHeader.ImageBase, pNtHeader->OptionalHeader.SizeOfImage,
				MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (PEHeader == NULL) {
				PEHeader = VirtualAllocEx(hProcess, NULL, pNtHeader->OptionalHeader.SizeOfImage,
					MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
				if (PEHeader == NULL) {
					if (OutErrorCode > NULL) {
						*OutErrorCode = FALIED_MEM_ALLOCATION;
					}
					CloseHandle(FileHandle);
					VirtualFree(FileBData, NULL, MEM_RELEASE);
					VirtualFreeEx(hProcess, PageRemoteCodeLoader, NULL, MEM_RELEASE);
					VirtualFreeEx(hProcess, PageRemoteCodeStructure, NULL, MEM_RELEASE);
					CMDLoader_Vars::Thread.unlock();
					return NULL;
				}
			}

			// Copy headers first 
			if (!WriteProcessMemory(hProcess, PEHeader, FileBData, pNtHeader->OptionalHeader.SizeOfHeaders, NULL)) {
				if (OutErrorCode > NULL) {
					*OutErrorCode = FALIED_INJECTION;
				}
				CloseHandle(FileHandle);
				VirtualFree(FileBData, NULL, MEM_RELEASE);
				VirtualFreeEx(hProcess, PEHeader, NULL, MEM_RELEASE);
				VirtualFreeEx(hProcess, PageRemoteCodeLoader, NULL, MEM_RELEASE);
				VirtualFreeEx(hProcess, PageRemoteCodeStructure, NULL, MEM_RELEASE);
				CMDLoader_Vars::Thread.unlock();
				return NULL;
			}

			// Sectiions
			if (pNtHeader->FileHeader.NumberOfSections > 0) {
				pSecHeader = IMAGE_FIRST_SECTION(pNtHeader);

				for (DWORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++, pSecHeader++)
				{
					// Check if the raw size and the virtual size is always more than 0.
					if (pSecHeader->SizeOfRawData > 0) {
						if (!WriteProcessMemory(hProcess, (LPVOID)((ULONG_PTR)PEHeader + pSecHeader->VirtualAddress),
							(LPVOID)((ULONG_PTR)FileBData + pSecHeader->PointerToRawData), min(pSecHeader->Misc.VirtualSize, pSecHeader->SizeOfRawData), NULL)) 
						{
							if (OutErrorCode > NULL) {
								*OutErrorCode = FALIED_INJECTION;
							}
							CloseHandle(FileHandle);
							VirtualFree(FileBData, NULL, MEM_RELEASE);
							VirtualFreeEx(hProcess, PEHeader, NULL, MEM_RELEASE);
							VirtualFreeEx(hProcess, PageRemoteCodeLoader, NULL, MEM_RELEASE);
							VirtualFreeEx(hProcess, PageRemoteCodeStructure, NULL, MEM_RELEASE);
							CMDLoader_Vars::Thread.unlock();
							return NULL;
						}
					}
				}
			}
			HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");

			InjectionStructure.LFlag = MANUAL_INJECTION;
			InjectionStructure.Signal = 0;

			InjectionStructure.__LoadLibA = (__LoadLibA__)GetProcAddress(hKernel32, "LoadLibraryA");
			InjectionStructure.__LoadLibExA = NULL;
			InjectionStructure.__GetProcAddress = (__GetProcAddress__)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetProcAddress");
			InjectionStructure.__FreeLibrary = NULL;

			InjectionStructure.LibraryN = nullptr;
			InjectionStructure.BaseAddr = PEHeader;
			InjectionStructure.pNt = (IMAGE_NT_HEADERS*)((ULONG_PTR)PEHeader + pDosHeader->e_lfanew);

			// Copy the filled structure
			if (!WriteProcessMemory(hProcess, PageRemoteCodeStructure, &InjectionStructure, sizeof(InjectionRC_Info), NULL)) {
				if (OutErrorCode > NULL) {
					*OutErrorCode = FALIED_INJECTION;
				}
				CloseHandle(FileHandle);
				VirtualFree(FileBData, NULL, MEM_RELEASE);
				VirtualFreeEx(hProcess, PEHeader, NULL, MEM_RELEASE);
				VirtualFreeEx(hProcess, PageRemoteCodeLoader, NULL, MEM_RELEASE);
				VirtualFreeEx(hProcess, PageRemoteCodeStructure, NULL, MEM_RELEASE);
				CMDLoader_Vars::Thread.unlock();
				return NULL;
			}

			// Write our code to the target process
			if (!WriteProcessMemory(hProcess, PageRemoteCodeLoader, CMDLoader_Service_Private::RemoteInjector, 0x7000, NULL)) {
				if (OutErrorCode > NULL) {
					*OutErrorCode = FALIED_INJECTION;
				}
				CloseHandle(FileHandle);
				VirtualFree(FileBData, NULL, MEM_RELEASE);
				VirtualFreeEx(hProcess, PEHeader, NULL, MEM_RELEASE);
				VirtualFreeEx(hProcess, PageRemoteCodeLoader, NULL, MEM_RELEASE);
				VirtualFreeEx(hProcess, PageRemoteCodeStructure, NULL, MEM_RELEASE);
				CMDLoader_Vars::Thread.unlock();
				return NULL;
			}
			RemoteThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)PageRemoteCodeLoader, PageRemoteCodeStructure, 0, NULL);
			if (RemoteThread == NULL) {
				if (OutErrorCode > NULL) {
					*OutErrorCode = FALIED_REMOTE_THREAD_CREATION;
				}
				CloseHandle(FileHandle);
				VirtualFree(FileBData, NULL, MEM_RELEASE);
				VirtualFreeEx(hProcess, PEHeader, NULL, MEM_RELEASE);
				VirtualFreeEx(hProcess, PageRemoteCodeLoader, NULL, MEM_RELEASE);
				VirtualFreeEx(hProcess, PageRemoteCodeStructure, NULL, MEM_RELEASE);
				CMDLoader_Vars::Thread.unlock();
				return NULL;
			}

			// Wait for the finished signal 
			while (InjectionStructure.Signal == 0)
			{
				if (!ReadProcessMemory(hProcess, PageRemoteCodeStructure, &InjectionStructure, sizeof(InjectionRC_Info), NULL)) {
					InjectionStructure.Signal = WARN_NO_RETURN_SIGNAL;
					break;
				}
				// Sleep for 1 second and try again 
				Sleep(1000);
			}

			if (OutErrorCode > NULL) {
				*OutErrorCode = InjectionStructure.Signal;
			}

			// Wait the thread for finish 
			WaitForSingleObject(RemoteThread, INFINITE);

			if (InjectionStructure.Signal == SUCCESS_RETURNED) {

				// Fill the informations struct
				OutMapInfo->StatusLoaded = true;
				OutMapInfo->PID = GetProcessId(hProcess);
				OutMapInfo->MBaseAddress = InjectionStructure.BaseAddr;
				OutMapInfo->LFlag = MANUAL_INJECTION;

				CloseHandle(FileHandle);

				VirtualFree(FileBData, NULL, MEM_RELEASE);
				VirtualFreeEx(hProcess, PageRemoteCodeLoader, NULL, MEM_RELEASE);
				VirtualFreeEx(hProcess, PageRemoteCodeStructure, NULL, MEM_RELEASE);

				CMDLoader_Vars::CurrentID++;
				CMDLoader_Vars::Thread.unlock();
				return CMDLoader_Vars::CurrentID;
			}

			CloseHandle(FileHandle);

			VirtualFree(FileBData, NULL, MEM_RELEASE);
			VirtualFreeEx(hProcess, PageRemoteCodeLoader, NULL, MEM_RELEASE);
			VirtualFreeEx(hProcess, PageRemoteCodeStructure, NULL, MEM_RELEASE);

			CMDLoader_Vars::Thread.unlock();
			return NULL;
		}
		else
		{
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_INVALID_PARAMETER;
			}
			VirtualFreeEx(hProcess, PageRemoteCodeLoader, NULL, MEM_RELEASE);
			VirtualFreeEx(hProcess, PageRemoteCodeStructure, NULL, MEM_RELEASE);
			CMDLoader_Vars::Thread.unlock();
			return NULL;
		}
	}

	// Init And shut down
	bool ServiceGlobalInit(int32_t* OutErrorCode)
	{
		// Safe thread 
		CMDLoader_Vars::Thread.lock();

		if (!CMDLoader_Vars::Inited)
		{
			if (!CMDLoader_Vars::RegisteredModules.empty()) {
				CMDLoader_Vars::RegisteredModules.clear();
			}
			if (OutErrorCode > NULL) {
				*OutErrorCode = NULL;
			}
			CMDLoader_Vars::Inited = true;
			CMDLoader_Vars::CurrentID = NULL;
			CMDLoader_Vars::Thread.unlock();
			return true;
		}
		else
		{
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_ALREADY_INITIALIZED;
			}
		}
		CMDLoader_Vars::Thread.unlock();
		return false;
	}
	bool ServiceGlobalShutDown(int32_t* OutErrorCode)
	{
		// Safe thread 
		CMDLoader_Vars::Thread.lock();

		if (CMDLoader_Vars::Inited)
		{
			if (OutErrorCode > NULL) {
				*OutErrorCode = NULL;
			}

			CMDLoader_Vars::Inited = false;
			CMDLoader_Vars::CurrentID = NULL;
			CMDLoader_Vars::Thread.unlock();
			return true;
		}
		else
		{
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_NEEDS_INITIALIZATION;
			}
		}
		CMDLoader_Vars::Thread.unlock();
		return false;
	}

	// Informations and helpers
	bool RetrieveProcessHandleByPID(DWORD InPID, HANDLE* OutHandle, int32_t* OutErrorCode)
	{
		// Paramaters first checks 
		if (InPID <= 0) {
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_INVALID_PARAMETER;
			}
			return false;
		}
		if (!OutHandle) {
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_INVALID_PARAMETER;
			}
			return false;
		}

		// Check if the service is started
		if (!CMDLoader_Vars::Inited) {
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_NEEDS_INITIALIZATION;
			}
			return false;
		}

		// Safe thread 
		CMDLoader_Vars::Thread.lock();

		// Declare some variables 
		HANDLE hSnapshot;
		HANDLE hProcess;
		PROCESSENTRY32 Processes = { 0 };

		hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
		if (hSnapshot == INVALID_HANDLE_VALUE) {
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_HANDLE_INVALID;
			}
			CMDLoader_Vars::Thread.unlock();
			return false;
		}

		Processes.dwSize = sizeof(PROCESSENTRY32);

		if (Process32First(hSnapshot, &Processes))
		{
			do
			{
				if (Processes.th32ProcessID == InPID)
				{
					hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, InPID);
					if (hProcess == INVALID_HANDLE_VALUE) {
						if (OutErrorCode > NULL) {
							*OutErrorCode = FALIED_HANDLE_INVALID;
						}
						CloseHandle(hSnapshot);
						CMDLoader_Vars::Thread.unlock();
						return false;
					}
					if (OutErrorCode > NULL) {
						*OutErrorCode = NULL;
					}
					*OutHandle = hProcess;
					CloseHandle(hSnapshot);
					CMDLoader_Vars::Thread.unlock();
					return true;
				}
			} while (Process32Next(hSnapshot, &Processes));
		}
		CloseHandle(hSnapshot);
		if (OutErrorCode > NULL) {
			*OutErrorCode = FALIED_PROCESS_NOT_FOUND;
		}
		CMDLoader_Vars::Thread.unlock();
		return false;
	}
	bool RetrieveProcessHandleByName(const wchar_t* InPName, HANDLE* OutHandle, int32_t* OutErrorCode)
	{
		// Paramaters first checks 
		if (!InPName) {
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_INVALID_PARAMETER;
			}
			return false;
		}
		if (!OutHandle) {
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_INVALID_PARAMETER;
			}
			return false;
		}

		// Check if the service is started
		if (!CMDLoader_Vars::Inited) {
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_NEEDS_INITIALIZATION;
			}
			return false;
		}

		// Safe thread 
		CMDLoader_Vars::Thread.lock();

		// Declare some variables 
		HANDLE hSnapshot;
		HANDLE hProcess;
		PROCESSENTRY32 Processes = { 0 };

		hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
		if (hSnapshot == INVALID_HANDLE_VALUE) {
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_HANDLE_INVALID;
			}
			CMDLoader_Vars::Thread.unlock();
			return false;
		}

		Processes.dwSize = sizeof(PROCESSENTRY32);

		if (Process32First(hSnapshot, &Processes))
		{
			do
			{
				if (lstrcmp(Processes.szExeFile, InPName) == 0)
				{
					hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Processes.th32ProcessID);
					if (hProcess == INVALID_HANDLE_VALUE) {
						if (OutErrorCode > NULL) {
							*OutErrorCode = FALIED_HANDLE_INVALID;
						}
						CloseHandle(hSnapshot);
						CMDLoader_Vars::Thread.unlock();
						return false;
					}
					if (OutErrorCode > NULL) {
						*OutErrorCode = NULL;
					}
					*OutHandle = hProcess;
					CloseHandle(hSnapshot);
					CMDLoader_Vars::Thread.unlock();
					return true;
				}
			} while (Process32Next(hSnapshot, &Processes));
		}
		CloseHandle(hSnapshot);
		if (OutErrorCode > NULL) {
			*OutErrorCode = FALIED_PROCESS_NOT_FOUND;
		}
		CMDLoader_Vars::Thread.unlock();
		return false;
	}
	bool RetrieveModuleInfoByID(ModuleMap_Info* OutputInfo, int32_t MID, int32_t* OutErrorCode)
	{
		// Paramaters
		if (!OutputInfo) {
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_INVALID_PARAMETER;
			}
			return false;
		}
		if (MID <= 0) {
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_INVALID_PARAMETER;
			}
			return false;
		}

		// Check if the service is started
		if (!CMDLoader_Vars::Inited) {
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_NEEDS_INITIALIZATION;
			}
			return false;
		}

		// Safe thread 
		CMDLoader_Vars::Thread.lock();

		for (auto iter = CMDLoader_Vars::RegisteredModules.begin(); iter != CMDLoader_Vars::RegisteredModules.end(); iter++)
		{
			if (iter->first == MID) {
				CopyMemory(OutputInfo, &iter->second, sizeof(ModuleMap_Info));
				if (OutErrorCode > NULL) {
					*OutErrorCode = NULL;
				}
				CMDLoader_Vars::Thread.unlock();
				return true;
			}
		}
		if (OutErrorCode > NULL) {
			*OutErrorCode = FALIED_MODULE_NOT_FOUND;
		}
		CMDLoader_Vars::Thread.unlock();
		return false;
	}
	bool RetrieveModuleIDByInfo(ModuleMap_Info* InputInfo, int32_t* OutMID, int32_t* OutErrorCode)
	{
		// Paramaters
		if (!InputInfo) {
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_INVALID_PARAMETER;
			}
			return false;
		}
		if (!OutMID) {
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_INVALID_PARAMETER;
			}
			return false;
		}

		// Check if the service is started
		if (!CMDLoader_Vars::Inited) {
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_NEEDS_INITIALIZATION;
			}
			return false;
		}

		// Safe thread 
		CMDLoader_Vars::Thread.lock();

		for (auto iter = CMDLoader_Vars::RegisteredModules.begin(); iter != CMDLoader_Vars::RegisteredModules.end(); iter++)
		{
			if (memcmp(&iter->second, InputInfo, sizeof(ModuleMap_Info)) == 0) {
				*OutMID = iter->first;
				if (OutErrorCode > NULL) {
					*OutErrorCode = NULL;
				}
				CMDLoader_Vars::Thread.unlock();
				return true;
			}
		}
		if (OutErrorCode > NULL) {
			*OutErrorCode = FALIED_MODULE_NOT_FOUND;
		}
		CMDLoader_Vars::Thread.unlock();
		return false;
	}
	bool RetrieveRunningProcessesList(std::multimap<DWORD, std::string> &DataList)
	{
		// Vars
		DWORD aProcesses[1024], cbNeeded, cProcesses;
		HANDLE hProcess = INVALID_HANDLE_VALUE;
		unsigned int i;

		// Thread safe 
		CMDLoader_Vars::Thread.lock();

		// Enum
		if (EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
		{
			if (DataList.size() > 0)
				DataList.clear();

			cProcesses = cbNeeded / sizeof(DWORD);
			for (i = 0; i < cProcesses; i++)
			{
				if (aProcesses[i] != 0)
				{
					CHAR ProcNameFormat[MAX_PATH] = { "Unknown" };
					CHAR OutString[1024] = { 0 };
					bool Print = false;
					int32_t ErrorC;

					hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
						PROCESS_VM_READ,
						FALSE, aProcesses[i]);
					if (hProcess != NULL)
					{
						HMODULE hMod;
						DWORD cbNeeded;

						if (EnumProcessModules(hProcess, &hMod, sizeof(hMod),
							&cbNeeded))
						{
							if (CMDLoader_Service_Private::IsProcessSameArch(hProcess, (void*)hMod, &ErrorC)) {
								if (ErrorC == NULL) {
									Print = true;

									GetModuleBaseNameA(hProcess, hMod, ProcNameFormat,
										sizeof(ProcNameFormat) / sizeof(CHAR));
								}
							}
						}
						CloseHandle(hProcess);
					}
					if (Print) {
						std::sprintf(OutString, "%u: %s", aProcesses[i], ProcNameFormat);
						DataList.insert(std::make_pair(aProcesses[i], OutString));
					}
				}
			}
			CMDLoader_Vars::Thread.unlock();
			return true;
		}
		CMDLoader_Vars::Thread.unlock();
		return false;
	}

	// Process helpers
	bool StartANewProcess(const char* InPName, char* InPCommandLine, PROCESS_INFORMATION* OutProcessInfo, int32_t* OutErrorCode)
	{
		// Paramaters
		if (!InPName) {
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_INVALID_PARAMETER;
			}
			return false;
		}
		if (!InPCommandLine) {
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_INVALID_PARAMETER;
			}
			return false;
		}
		if (!OutProcessInfo) {
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_INVALID_PARAMETER;
			}
			return false;
		}

		// Check if the service is started
		if (!CMDLoader_Vars::Inited) {
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_NEEDS_INITIALIZATION;
			}
			return false;
		}

		// Safe thread 
		CMDLoader_Vars::Thread.lock();

		// Declare some variables 
		HANDLE hSnapshot;
		HANDLE hProcess;
		STARTUPINFOA info = { sizeof(info) };
		PROCESS_INFORMATION processInfo;

		if (GetFileAttributesA(InPName) == INVALID_FILE_ATTRIBUTES) {
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_FILE_NOT_EXISTS;
			}
			CMDLoader_Vars::Thread.unlock();
			return false;
		}
		if (!CreateProcessA(InPName, InPCommandLine, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &info, &processInfo)) {
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_STARTING_PROCESS;
			}
			CMDLoader_Vars::Thread.unlock();
			return false;
		}
		CopyMemory(OutProcessInfo, &processInfo, sizeof(PROCESS_INFORMATION));
		if (OutErrorCode > NULL) {
			*OutErrorCode = NULL;
		}
		CMDLoader_Vars::Thread.unlock();
		return true;
	}
	bool DetachStartedProcess(PROCESS_INFORMATION* InProcessInfo, int32_t* OutErrorCode)
	{
		// Paramaters
		if (!InProcessInfo) {
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_INVALID_PARAMETER;
			}
			return false;
		}

		// Check if the service is started
		if (!CMDLoader_Vars::Inited) {
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_NEEDS_INITIALIZATION;
			}
			return false;
		}

		// Safe thread 
		CMDLoader_Vars::Thread.lock();

		// Firstly resume the thread 
		if (ResumeThread(InProcessInfo->hThread) == (DWORD)-1) {
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_RESUMING_THREAD;
			}
			CMDLoader_Vars::Thread.unlock();
			return false;
		}
		if (!CloseHandle(InProcessInfo->hProcess)) {
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_CLOSING_HANDLE;
			}
			CMDLoader_Vars::Thread.unlock();
			return false;
		}
		if (!CloseHandle(InProcessInfo->hThread)) {
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_CLOSING_HANDLE;
			}
			CMDLoader_Vars::Thread.unlock();
			return false;
		}

		if (OutErrorCode > NULL) {
			*OutErrorCode = NULL;
		}
		CMDLoader_Vars::Thread.unlock();
		return true;
	}
	bool CloseProcessHandle(HANDLE hProcess, int32_t* OutErrorCode)
	{
		// Just close the handle 
		if (!CloseHandle(hProcess)) {
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_CLOSING_HANDLE;
			}
			return false;
		}
		if (OutErrorCode > NULL) {
			*OutErrorCode = NULL;
		}
		return true;
	}

	bool ServiceRegisterModuleInformation(ModuleMap_Info* InputInfo, int32_t MID, int32_t* OutErrorCode)
	{
		// Paramaters
		if (!InputInfo) {
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_INVALID_PARAMETER;
			}
			return false;
		}
		if (MID <= 0) {
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_INVALID_PARAMETER;
			}
			return false;
		}

		// Check if the service is started
		if (!CMDLoader_Vars::Inited) {
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_NEEDS_INITIALIZATION;
			}
			return false;
		}

		// Safe thread 
		CMDLoader_Vars::Thread.lock();

		// Vars
		ModuleMap_Info MapInfo;
		CopyMemory(&MapInfo, InputInfo, sizeof(ModuleMap_Info));

		// Check if already exists first 
		for (auto iter = CMDLoader_Vars::RegisteredModules.begin(); iter != CMDLoader_Vars::RegisteredModules.end(); iter++)
		{
			if (memcmp(&iter->second, InputInfo, sizeof(ModuleMap_Info)) == 0) {
				if (OutErrorCode > NULL) {
					*OutErrorCode = FALIED_ALREADY_EXISTS;
				}
				CMDLoader_Vars::Thread.unlock();
				return false;
			}
			if (iter->first == MID) {
				if (OutErrorCode > NULL) {
					*OutErrorCode = FALIED_ALREADY_EXISTS;
				}
				CMDLoader_Vars::Thread.unlock();
				return false;
			}
		}
		CMDLoader_Vars::RegisteredModules.insert(std::make_pair(MID, MapInfo));
		if (OutErrorCode > NULL) {
			*OutErrorCode = NULL;
		}
		CMDLoader_Vars::Thread.unlock();
		return true;
	}
	bool ServiceUnRegisterModuleInformation(int32_t MID, int32_t* OutErrorCode)
	{
		// Paramaters
		if (MID <= 0) {
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_INVALID_PARAMETER;
			}
			return false;
		}

		// Check if the service is started
		if (!CMDLoader_Vars::Inited) {
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_NEEDS_INITIALIZATION;
			}
			return false;
		}

		// Safe thread 
		CMDLoader_Vars::Thread.lock();

		// Check if already exists first 
		for (auto iter = CMDLoader_Vars::RegisteredModules.begin(); iter != CMDLoader_Vars::RegisteredModules.end(); iter++)
		{
			if (iter->first == MID) {
				CMDLoader_Vars::RegisteredModules.erase(iter);
				if (OutErrorCode > NULL) {
					*OutErrorCode = NULL;
				}
				CMDLoader_Vars::Thread.unlock();
				return true;
			}
		}
		if (OutErrorCode > NULL) {
			*OutErrorCode = FALIED_MODULE_NOT_FOUND;
		}
		CMDLoader_Vars::Thread.unlock();
		return false;
	}

	// Error handler
	const char* RetrieveErrorCodeString(int32_t InErrorCode)
	{
		const char* ErrorString;
		switch (InErrorCode)
		{
		case NULL:
			ErrorString = "SUCCESS_NO_ERROR";
			break;
		case FALIED_NEEDS_INITIALIZATION:
			ErrorString = "FALIED_NEEDS_INITIALIZATION";
			break;
		case FALIED_ALREADY_INITIALIZED:
			ErrorString = "FALIED_ALREADY_INITIALIZED";
			break;
		case FALIED_BUFFER_CREATION:
			ErrorString = "FALIED_BUFFER_CREATION";
			break;
		case FALIED_INVALID_PARAMETER:
			ErrorString = "FALIED_INVALID_PARAMETER";
			break;
		case FALIED_ALREADY_EXISTS:
			ErrorString = "FALIED_ALREADY_EXISTS";
			break;
		case FALIED_NOT_EXISTS:
			ErrorString = "FALIED_NOT_EXISTS";
			break;
		case FALIED_FREE_MEMORY:
			ErrorString = "FALIED_FREE_MEMORY";
			break;
		case FALIED_UNLOAD:
			ErrorString = "FALIED_UNLOAD";
			break;
		case FALIED_LOAD:
			ErrorString = "FALIED_LOAD";
			break;
		case FALIED_NOT_ALLOWED:
			ErrorString = "FALIED_NOT_ALLOWED";
			break;
		case FALIED_ALLOCATION:
			ErrorString = "FALIED_ALLOCATION";
			break;
		case FALIED_NO_ACCESS:
			ErrorString = "FALIED_NO_ACCESS";
			break;
		case FALIED_MODULE_NOT_FOUND:
			ErrorString = "FALIED_MODULE_NOT_FOUND";
			break;
		case FALIED_FUNCTION_NOT_FOUND:
			ErrorString = "FALIED_FUNCTION_NOT_FOUND";
			break;
		case FALIED_OUT_RANGE:
			ErrorString = "FALIED_OUT_RANGE";
			break;
		case FALIED_MEM_ALLOCATION:
			ErrorString = "FALIED_MEM_ALLOCATION";
			break;
		case FALIED_INJECTION:
			ErrorString = "FALIED_INJECTION";
			break;
		case FALIED_REMOTE_THREAD_CREATION:
			ErrorString = "FALIED_REMOTE_THREAD_CREATION";
			break;
		case FALIED_FILE_HANDLE_INVALID:
			ErrorString = "FALIED_FILE_HANDLE_INVALID";
			break;
		case FALIED_FILE_READMAP:
			ErrorString = "FALIED_FILE_READMAP";
			break;
		case FALIED_INVALID_PE:
			ErrorString = "FALIED_INVALID_PE";
			break;
		case FALIED_INVALID_PE_ARCH:
			ErrorString = "FALIED_INVALID_PE_ARCH";
			break;
		case FALIED_LIBRARY_UNLOAD:
			ErrorString = "FALIED_LIBRARY_UNLOAD";
			break;
		case FALIED_HANDLE_INVALID:
			ErrorString = "FALIED_HANDLE_INVALID";
			break;
		case FALIED_PROCESS_NOT_FOUND:
			ErrorString = "FALIED_PROCESS_NOT_FOUND";
			break;
		case FALIED_FILE_NOT_EXISTS:
			ErrorString = "FALIED_FILE_NOT_EXISTS";
			break;
		case FALIED_STARTING_PROCESS:
			ErrorString = "FALIED_STARTING_PROCESS";
			break;
		case FALIED_RESUMING_THREAD:
			ErrorString = "FALIED_RESUMING_THREAD";
			break;
		case FALIED_CLOSING_HANDLE:
			ErrorString = "FALIED_CLOSING_HANDLE";
			break;
		case FALIED_MODULE_LOAD:
			ErrorString = "FALIED_MODULE_LOAD";
			break;
		case FALIED_FILE_READ:
			ErrorString = "FALIED_FILE_READ";
			break;
		case FALIED_READING_PROCESS_MEM:
			ErrorString = "FALIED_READING_PROCESS_MEM";
			break;
		case WARN_32_BIT:
			ErrorString = "WARN_32_BIT";
			break;
		case WARN_NO_RETURN_SIGNAL:
			ErrorString = "WARN_NO_RETURN_SIGNAL";
			break;
		case SUCCESS_RETURNED:
			ErrorString = "SUCCESS_RETURNED";
			break;
		default:
			ErrorString = "Unknown error";
			break;
		}
		return ErrorString;
	}
}