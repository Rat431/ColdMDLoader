// Injector.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <sstream>
#include "ColdMDLoader/ColdMDLoader.h"

const char* GetFileName(const char* Path)
{
	return Path;
}

void Loader()
{
	DWORD PID;
	unsigned int Flag = 0;
	int32_t ErrorCode;

	std::string RInput = "";
	std::string FPath = "";
	std::string DllFile = "";

	// Start by asking user which injection should be performed.
	std::cout << "Type 1 to start a new process, type 2 to open an existing one: ";
	while (1) {
		std::getline(std::cin, RInput);

		std::stringstream str(RInput);
		if (!(str >> Flag)) {
			system("cls");
			std::cout << "Invalie flag, please try again: ";
			Sleep(10);
			continue;
		}
		if (Flag == 1) {
			system("cls");
			std::cout << "Please enter the target file path: ";
			std::getline(std::cin, FPath);
			system("cls");
			std::cout << "Please enter the target dll file path: ";
			std::getline(std::cin, DllFile);
			system("cls");

			std::cout << "The following file will be started: " << GetFileName(FPath.c_str()) << std::endl;
			std::cout << "The following dll file will be injected: " << GetFileName(DllFile.c_str()) << std::endl;
			Sleep(10);

			// Init the loader service
			if (CMDLoader_Service::ServiceGlobalInit(&ErrorCode)) {
				std::cout << "Service has been initialized!" << std::endl;
				Sleep(10);
				PROCESS_INFORMATION prc;
				if (CMDLoader_Service::StartANewProcess(FPath.c_str(), NULL, &prc, &ErrorCode)) {
					std::cout << "Process has been started with the following PID: 0x" << std::hex << prc.dwProcessId << std::endl;
					Sleep(10);
					ModuleMap_Info mapinfo;
					int32_t MID = CMDLoader_Service::InitModuleInjection(prc.hProcess, DllFile.c_str(), MANUAL_INJECTION, &mapinfo, &ErrorCode);
					if (MID > 0) {
						std::cout << "The module has been injected!" << std::endl;
						Sleep(10);
						if (CMDLoader_Service::DetachStartedProcess(&prc, &ErrorCode)) {
							std::cout << "The process is now running with the requested module!" << std::endl;
							Sleep(10);
							if (CMDLoader_Service::ServiceGlobalShutDown(&ErrorCode)) {
								std::cout << "SUCCESS!" << std::endl;
								std::cout << std::endl;
								return;
							}
							else {
								std::cout << "Couldn't shutdown the service with the following reason: " << CMDLoader_Service::RetrieveErrorCodeString(ErrorCode) << std::endl;
								std::cout << std::endl;
								return;
							}
						}
						else {
							std::cout << "Couldn't run the process with the following reason: " << CMDLoader_Service::RetrieveErrorCodeString(ErrorCode) << std::endl;
							std::cout << std::endl;
							return;
						}
					}
					else {
						std::cout << "The requested module can not be injected with the following reason: " << CMDLoader_Service::RetrieveErrorCodeString(ErrorCode) << std::endl;
						std::cout << std::endl;
						return;
					}
				}
				else {
					std::cout << "The process can not be started with the following reason: " << CMDLoader_Service::RetrieveErrorCodeString(ErrorCode) << std::endl;
					std::cout << std::endl;
					return;
				}
			}
			else {
				std::cout << "CMDLoader_Service init falied with the following reason: " << CMDLoader_Service::RetrieveErrorCodeString(ErrorCode) << std::endl;
				std::cout << std::endl;
				return;
			}
		}
		else if (Flag == 2) {
			system("cls");
			std::cout << "Please enter the target process PID: ";
			while (1) {
				std::getline(std::cin, RInput);

				std::stringstream str(RInput);
				if (!(str >> PID)) {
					system("cls");
					std::cout << "Invalie PID value, please try again: ";
					Sleep(10);
				}
				else {
					break;
				}
			}
			system("cls");
			std::cout << "Please enter the target dll file path: ";
			std::getline(std::cin, DllFile);

			system("cls");
			std::cout << "The following PID will be attached: 0x" << std::hex << PID << std::endl;
			std::cout << "The following dll file will be injected: " << GetFileName(DllFile.c_str()) << std::endl;
			Sleep(10);

			// Init the loader service
			if (CMDLoader_Service::ServiceGlobalInit(&ErrorCode)) {
				std::cout << "Service has been initialized!" << std::endl;
				Sleep(10);
				HANDLE hProcess;
				if (CMDLoader_Service::RetrieveProcessHandleByPID(PID, &hProcess, &ErrorCode)) {
					ModuleMap_Info mapinfo;
					int32_t MID = CMDLoader_Service::InitModuleInjection(hProcess, DllFile.c_str(), MANUAL_INJECTION, &mapinfo, &ErrorCode);
					if (MID > 0) {
						std::cout << "The module has been injected!" << std::endl;
						Sleep(10);
						if (CMDLoader_Service::CloseProcessHandle(hProcess, &ErrorCode)) {
							std::cout << "The handle has been closed!" << std::endl;
							Sleep(10);
							if (CMDLoader_Service::ServiceGlobalShutDown(&ErrorCode)) {
								std::cout << "SUCCESS!" << std::endl;
								std::cout << std::endl;
								return;
							}
							else {
								std::cout << "Couldn't shutdown the service with the following reason: " << CMDLoader_Service::RetrieveErrorCodeString(ErrorCode) << std::endl;
								std::cout << std::endl;
								return;
							}
						}
						else {
							std::cout << "Couldn't close the process handle with the following reason: " << CMDLoader_Service::RetrieveErrorCodeString(ErrorCode) << std::endl;
							std::cout << std::endl;
							return;
						}
					}
					else {
						std::cout << "The requested module can not be injected with the following reason: " << CMDLoader_Service::RetrieveErrorCodeString(ErrorCode) << std::endl;
						std::cout << std::endl;
						return;
					}
				}
				else {
					std::cout << "Couldn't get an handle to the requested PID with the following reason: " << CMDLoader_Service::RetrieveErrorCodeString(ErrorCode) << std::endl;
					std::cout << std::endl;
					return;
				}
			}
			else {
				std::cout << "CMDLoader_Service init falied with the following reason: " << CMDLoader_Service::RetrieveErrorCodeString(ErrorCode) << std::endl;
				std::cout << std::endl;
				return;
			}
		}
		else {
			std::cout << "Invalie flag, please try again: ";
			Sleep(10);
			continue;
		}
	}
}

int main(int argc, char** argv)
{
	HANDLE hConsole;
	CONSOLE_FONT_INFOEX fontb;
	CONSOLE_FONT_INFOEX font;

	// Title first 
	SetConsoleTitleA("CMDL_Loader");

	// Setup console styles
	hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	if (hConsole == INVALID_HANDLE_VALUE) {
		std::cout << "Falied to setup the console style!" << std::endl;
		return -1;
	}

	// Console fonts
	GetCurrentConsoleFontEx(hConsole, false, &fontb);
	memcpy(&font, &fontb, sizeof(CONSOLE_FONT_INFOEX));
	font.dwFontSize.X = 7;
	font.dwFontSize.Y = 12;

	SetCurrentConsoleFontEx(hConsole, false, &fontb);
	SetConsoleTextAttribute(hConsole, 12);

	// Run the loader
	Loader();
	system("pause");
	
	return 0;
}