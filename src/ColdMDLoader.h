/*
	Copyright (c) 2019 Rat431 (https://github.com/Rat431).
	This software is under the MIT license, for more informations check the LICENSE file.
*/

#pragma once
#include <Windows.h>
#include <iostream>
#include <stdint.h>
#include <map>
#include <mutex>
#include <tlhelp32.h>
#include <psapi.h>

#define REMOTECODEF _stdcall
#define STANDARD_INJECTION 1
#define MANUAL_INJECTION 2
#define UNLOAD_LIBRARY 44

// Errors
enum CMDL_Error_Info
{
	FALIED_NEEDS_INITIALIZATION = 40,
	FALIED_ALREADY_INITIALIZED,
	FALIED_BUFFER_CREATION,
	FALIED_INVALID_PARAMETER,
	FALIED_ALREADY_EXISTS,
	FALIED_NOT_EXISTS,
	FALIED_FREE_MEMORY,
	FALIED_UNLOAD,
	FALIED_LOAD,
	FALIED_NOT_ALLOWED,
	FALIED_ALLOCATION,
	FALIED_NO_ACCESS,
	FALIED_MODULE_NOT_FOUND,
	FALIED_FUNCTION_NOT_FOUND,
	FALIED_OUT_RANGE,
	FALIED_MEM_ALLOCATION,
	FALIED_INJECTION,
	FALIED_REMOTE_THREAD_CREATION,
	FALIED_FILE_HANDLE_INVALID,
	FALIED_FILE_READMAP,
	FALIED_INVALID_PE,
	FALIED_INVALID_PE_ARCH,
	FALIED_LIBRARY_UNLOAD,
	FALIED_HANDLE_INVALID,
	FALIED_PROCESS_NOT_FOUND,
	FALIED_FILE_NOT_EXISTS,
	FALIED_STARTING_PROCESS,
	FALIED_RESUMING_THREAD,
	FALIED_CLOSING_HANDLE,
	FALIED_MODULE_LOAD,
	FALIED_FILE_READ,

	WARN_32_BIT,
	WARN_NO_RETURN_SIGNAL,

	SUCCESS_RETURNED
};

struct ModuleMap_Info
{
	bool StatusLoaded;
	int32_t LFlag;
	void* MBaseAddress;
	DWORD PID;
};

namespace CMDLoader_Service
{
	// Mapping functions 
	int32_t InitModuleInjection(HANDLE hProcess, const char* DllFileName, int32_t LFlag, ModuleMap_Info* OutMapInfo, int32_t* OutErrorCode);
	
	// Init And shut down
	bool ServiceGlobalInit(int32_t* OutErrorCode);
	bool ServiceGlobalShutDown(int32_t* OutErrorCode);

	// Informations and helpers
	bool RetrieveProcessHandleByPID(DWORD InPID, HANDLE* OutHandle, int32_t* OutErrorCode);
	bool RetrieveProcessHandleByName(const wchar_t* InPName, HANDLE* OutHandle, int32_t* OutErrorCode);
	bool RetrieveModuleInfoByID(ModuleMap_Info* OutputInfo, int32_t MID, int32_t* OutErrorCode);
	bool RetrieveModuleIDByInfo(ModuleMap_Info* InputInfo, int32_t* OutMID, int32_t* OutErrorCode);
	bool RetrieveRunningProcessesList(std::multimap<DWORD, std::string> &DataList);

	// Process helpers
	bool StartANewProcess(const char* InPName, char* InPCommandLine, PROCESS_INFORMATION* OutProcessInfo, int32_t* OutErrorCode);
	bool DetachStartedProcess(PROCESS_INFORMATION* InProcessInfo, int32_t* OutErrorCode);
	bool CloseProcessHandle(HANDLE hProcess, int32_t* OutErrorCode);

	bool ServiceRegisterModuleInformation(ModuleMap_Info* InputInfo, int32_t MID, int32_t* OutErrorCode);
	bool ServiceUnRegisterModuleInformation(int32_t MID, int32_t* OutErrorCode);

	// Error handler
	const char* RetrieveErrorCodeString(int32_t InErrorCode);
}