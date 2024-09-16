#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <injector\injector.hpp>
#include <injector\assembly.hpp>
#include <injector\calling.hpp>
#include <map>
#include <thread>
#include <string>
#include <chrono>
#include <atomic>
#include <mutex>
#include <time.h>
#include <fstream>

//std::fstream testdebug;

char *nullchar = "\0\0\0";

std::thread waitm;
uint32_t cleoTextAddress = 0, sampAddress = 0;

inline void MakeJZ(injector::memory_pointer_tr at, injector::memory_pointer_raw dest, bool vp = true)
{
	using namespace injector;
	WriteMemory<uint16_t>(at, 0x840F, vp);
	MakeRelativeOffset(at + 2, dest, 4, vp);
}

inline void MakeJNZ(injector::memory_pointer_tr at, injector::memory_pointer_raw dest, bool vp = true)
{
	using namespace injector;
	WriteMemory<uint16_t>(at, 0x850F, vp);
	MakeRelativeOffset(at + 2, dest, 4, vp);
}

inline void MakeJNP(injector::memory_pointer_tr at, injector::memory_pointer_raw dest, bool vp = true)
{
	using namespace injector;
	WriteMemory<uint16_t>(at, 0x8B0F, vp);
	MakeRelativeOffset(at + 2, dest, 4, vp);
}

std::atomic<uint32_t> result;
std::mutex loadm;
bool canProced;

void *returnHookAddr;
char *cleoresultfxt = 0;
int returnNow = 0;

char *keyBackup;
char *ecxBackup;

void testhook()
{
	//testdebug << "FXT" << std::endl;
	if (cleoresultfxt)
	{
		if (*cleoresultfxt != 0)
		{
			returnNow = 1;
			//testdebug << keyBackup << "  VALUE ->   " << cleoresultfxt << std::endl;
		}
		else{
			//testdebug << "FALHOU *******  " << keyBackup << std::endl;
			returnNow = 0;
		}
	}
	else
	{
		//testdebug << "FALHOU *******  " << keyBackup << std::endl;
		returnNow = 0;
	}

	//testdebug.flush();
}

void __declspec(naked) hookSystem()
{
	__asm
	{
		pop returnHookAddr

		pop keyBackup
		mov ecxBackup, ecx

		/*mov eax, keyBackup
		mov ecx, 0
		mov cl, byte ptr[eax]

		cmp ecx, 0
		je retnullstr*/

		push keyBackup

		call sampAddress
		mov cleoresultfxt, eax

		pushad
		call testhook
		popad

		cmp returnNow, 0
		jne rethooknow


		push keyBackup
		mov ecx, ecxBackup
		call cleoTextAddress
		mov cleoresultfxt, eax

	rethooknow:
		mov eax, cleoresultfxt

		push returnHookAddr
		ret

	retnullstr:
		mov eax, nullchar
		push returnHookAddr
		ret
	}
}

void waitchanges()
{
	std::lock_guard<std::mutex> l(loadm);
	result = (uint32_t)LoadLibraryA("CLEO.asi");
}

DWORD WINAPI waitsamp(LPVOID lpParam)
{
	try{
		DWORD old;
		VirtualProtect((void*)0x006A0050, 6, PAGE_EXECUTE_READWRITE, &old);
		while (true)
		{
			auto value = injector::ReadMemory<uint16_t>(0x006A0050);
			canProced = true;

			if (value == 0x25FF)
			{
				sampAddress = injector::ReadMemory<uint32_t>(injector::ReadMemory<uint32_t>(0x006A0052));

				injector::MakeJMP(0x006A0050, hookSystem);

				//testdebug << "CLEO " << std::to_string(cleoTextAddress) << std::endl;
				return 0;
			}
			else
			{
				/*auto ptr = injector::ReadMemory<uint32_t>(0x006A0051);

				if (ptr != cleoTextAddress)
				{
					return 1;
				}*/
			}

			Sleep(1);
		}
	}
	catch (...)
	{
		MessageBoxA(0, "error - http://bms.mixmods.com.br/t5400-testes-corrigir-fxt-no-samp", "Mod by Fabio / - http://bms.mixmods.com.br/", 0);

	}

	return 0;
}

void hook(uint32_t cleoaddr)
{
	cleoTextAddress = cleoaddr;

	canProced = false;

	DWORD r;

	HANDLE rh = CreateThread(
		NULL,                   // default security attributes
		0,                      // use default stack size  
		waitsamp,       // thread function name
		0,          // argument to thread function 
		0,                      // use default creation flags 
		&r);   // returns the thread identifier 


	std::this_thread::sleep_for(std::chrono::milliseconds(100));
}

bool hooked = false;

BOOL WINAPI DllMain(
	_In_  HINSTANCE hinstDLL,
	_In_  DWORD fdwReason,
	_In_  LPVOID lpvReserved
	){
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		if (GetModuleHandleA("samp") && !hooked)
		{
			hooked = true;
			DWORD old;
			VirtualProtect((void*)0x006A0050, 6, PAGE_EXECUTE_READWRITE, &old);

			cleoTextAddress = 0;
			//testdebug.open("testdebug.log", std::ios::out | std::ios::trunc);
			uint8_t opFirstByte = injector::ReadMemory<uint8_t>(0x006A0050);

			if (opFirstByte != 0x83)
			{
				hook(injector::ReadMemory<uint32_t>(0x006A0051) + 0x006A0055);
			}
			else
			{
				waitm = std::thread(waitchanges);

				std::this_thread::sleep_for(std::chrono::milliseconds(50));

				std::lock_guard<std::mutex> l(loadm);

				if (waitm.joinable())
					waitm.join();

				if (result != 0)
					hook(injector::ReadMemory<uint32_t>(0x006A0051) + 0x006A0055);
			}
		}
	}
	else
	{
		//MessageBoxA(0, "wat", std::to_string(fdwReason).c_str(), 0);
	}


	return true;
}