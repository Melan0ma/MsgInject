#pragma once
#ifndef __PE_HANDLER
#define __PE_HANDLER
#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>
class PEHandler
{
public:
	PEHandler(BYTE instType) : instanceType(instType) { };
	IMAGE_DOS_HEADER DosHeader;
	IMAGE_NT_HEADERS NtHeaders;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER OptionalHeader;
	HANDLE FileHandle;
	HANDLE MappingHandle;
	PBYTE MapView;
	long FileLength;
	void* ImageBase;
	HANDLE ProcessHandle;
	static DWORD GetInstance(DWORD, PEHandler*);
	static DWORD GetInstance(HANDLE, PEHandler*);
	//static DWORD GetInstance(LPVOID, PEHandler*);
	void GetSection(const char*, PIMAGE_SECTION_HEADER);
	void CreateSection(const char*, void*, size_t);
	//void RunOnMemory(HMODULE, LPWSTR = nullptr, DWORD*);
	static void PatchSection(PIMAGE_SECTION_HEADER, DWORD rOffset, size_t bytes, void* newData);
	~PEHandler();

private:
	BYTE instanceType = 0;
	static HANDLE getFileHandle(wchar_t* fn) {
		return CreateFile(fn, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	};
	static DWORD calcAlign(DWORD size, DWORD alignment, DWORD address) {
		if (!(size % alignment))
			return address + size;
		return address + (size / alignment + 1) * alignment;
	};

	static long GetFileSizeA(HANDLE fHandle) {
		LARGE_INTEGER lInt;
		if (GetFileSizeEx(fHandle, &lInt))
			return lInt.LowPart;
		return GetLastError();
	};

};
#endif
inline DWORD PEHandler::GetInstance(DWORD processId, PEHandler* instOut = nullptr) {
	MODULEENTRY32 mEntry;
	HANDLE hMod = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processId);
	mEntry.dwSize = sizeof(MODULEENTRY32);

	if (!Module32First(hMod, &mEntry)) {
		return 0x01;
	}
	HANDLE fHandle = getFileHandle(mEntry.szExePath);
	DWORD retData = GetInstance(fHandle, instOut);
	instOut->instanceType = 0x02;
	return retData;
}
/*
inline DWORD PEHandler::GetInstance(LPVOID pePointer, size_t peSize, PEHandler* instOut = nullptr) {
	if (pePointer == nullptr)
		return 0x06;

	if (peSize <= 97)
		return 0x07;

	PEHandler* pInst = new PEHandler(0x03);
	PIMAGE_DOS_HEADER tDosHead = PIMAGE_DOS_HEADER((PBYTE)pePointer);
	PIMAGE_NT_HEADERS tNtHead;

	if (tDosHead->e_magic != IMAGE_DOS_SIGNATURE)
		return 0x08;

	tNtHead = PIMAGE_NT_HEADERS(((PBYTE)pePointer) + tDosHead->e_lfanew);
	if (tNtHead->Signature != IMAGE_NT_SIGNATURE)
		return 0x09;

	pInst->DosHeader = *tDosHead;
	pInst->NtHeaders = *tNtHead;
	pInst->FileHeader = tNtHead->FileHeader;
	pInst->OptionalHeader = tNtHead->OptionalHeader;
	*instOut = *pInst;
	return 0;
}*/

inline DWORD PEHandler::GetInstance(HANDLE fHandle, PEHandler* instOut = nullptr)
{
	if (fHandle == INVALID_HANDLE_VALUE)
	{
		return 0x02;
	}
	PEHandler* pInst = new PEHandler(0x01);
	pInst->FileLength = GetFileSizeA(fHandle);
	PIMAGE_DOS_HEADER tDosHead;
	PIMAGE_NT_HEADERS tNtHead;
	pInst->FileHandle = fHandle;
	pInst->MappingHandle = CreateFileMapping(pInst->FileHandle, NULL, PAGE_READWRITE, 0, 0, NULL);
	if (pInst->MappingHandle == INVALID_HANDLE_VALUE) {
		CloseHandle(fHandle);
		CloseHandle(pInst->MappingHandle);
		return 0x03;
	}
	pInst->MapView = (PBYTE)MapViewOfFile(pInst->MappingHandle, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, NULL);
	tDosHead = PIMAGE_DOS_HEADER(pInst->MapView);
	if (tDosHead->e_magic != IMAGE_DOS_SIGNATURE) {
		return 0x04;
	}
	tNtHead = PIMAGE_NT_HEADERS(pInst->MapView + tDosHead->e_lfanew);
	if (tNtHead->Signature != IMAGE_NT_SIGNATURE) {
		return 0x05;
	}
	pInst->DosHeader = *tDosHead;
	pInst->NtHeaders = *tNtHead;
	pInst->FileHeader = tNtHead->FileHeader;
	pInst->OptionalHeader = tNtHead->OptionalHeader;
	*instOut = *pInst;
	return 0;
}


inline void PEHandler::GetSection(const char* name, PIMAGE_SECTION_HEADER sectOut = 0)
{
	IMAGE_SECTION_HEADER tSectHead;
	for (unsigned int i = 0; i < NtHeaders.FileHeader.NumberOfSections; i++) {
		char sName[8] = { 0 };

		tSectHead = *(PIMAGE_SECTION_HEADER(MapView + DosHeader.e_lfanew + 0xF8 + (i * 40)));;
		for (int l = 0; l < 8; l++)
			sName[l] = (char)tSectHead.Name[l];
		if (strcmp(sName, name) == 0)
		{
			*sectOut = tSectHead;
			break;
		}

	}
}

inline void PEHandler::CreateSection(const char* name, void* newData, size_t size)
{
	PBYTE peCopy = (PBYTE)malloc(FileLength);
	memcpy(peCopy, MapView, FileLength);
	PIMAGE_DOS_HEADER dh = PIMAGE_DOS_HEADER(peCopy);
	PIMAGE_NT_HEADERS nh = PIMAGE_NT_HEADERS(peCopy + dh->e_lfanew);
	PIMAGE_FILE_HEADER fh = PIMAGE_FILE_HEADER(peCopy + dh->e_lfanew + sizeof(DWORD));;
	PIMAGE_OPTIONAL_HEADER oh = PIMAGE_OPTIONAL_HEADER(peCopy + dh->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER fsh = PIMAGE_SECTION_HEADER(peCopy + dh->e_lfanew + 0xF8);
	PIMAGE_SECTION_HEADER lsh = PIMAGE_SECTION_HEADER(peCopy + dh->e_lfanew + 0xF8 + ((fh->NumberOfSections - 1) * 40));
	PIMAGE_SECTION_HEADER nsh = &fsh[fh->NumberOfSections];
	ZeroMemory(nsh, sizeof(IMAGE_SECTION_HEADER));
	memcpy(nsh->Name, name, 8);
	/*
		NEWLY ADDED
	*/
	DWORD imgBase = oh->ImageBase;
	DWORD ep = oh->AddressOfEntryPoint;
	DWORD oep = imgBase + ep;
	char pushAsm[] = "\x68";
	char espReg[] = "\xff\x24\x24";
	char hexOep[] = { oep >> 0 & 0xFF, oep >> 8 & 0xFF, oep >> 16 & 0xFF, oep >> 24 & 0xFF };
	/*
	*	NEW END
	*/
	nsh->VirtualAddress = calcAlign(lsh->Misc.VirtualSize, oh->SectionAlignment, lsh->VirtualAddress);
	nsh->PointerToRawData = calcAlign(lsh->SizeOfRawData, oh->FileAlignment, lsh->PointerToRawData);
	nsh->SizeOfRawData = calcAlign(oh->SectionAlignment, oh->FileAlignment, 0);
	nsh->Misc.VirtualSize = calcAlign(oh->SectionAlignment, oh->SectionAlignment, 0);
	nsh->Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
	fh->NumberOfSections++;
	oh->SizeOfImage = nsh->VirtualAddress + nsh->Misc.VirtualSize;
	oh->AddressOfEntryPoint = nsh->VirtualAddress;
	oh->DllCharacteristics ^= IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
	oh->DataDirectory[5].VirtualAddress = { 0 };
	oh->DataDirectory[5].Size = { 0 };
	nh->FileHeader.Characteristics |= IMAGE_FILE_RELOCS_STRIPPED;
	oh->DllCharacteristics ^= IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
	oh->DataDirectory[4].VirtualAddress = { 0 };
	oh->DataDirectory[4].Size = { 0 };
	SetFilePointer(FileHandle, 0, 0, FILE_BEGIN);
	WriteFile(FileHandle, peCopy, FileLength, nullptr, 0);
	SetFilePointer(FileHandle, nsh->PointerToRawData, 0, FILE_BEGIN);
	PBYTE rawData = (PBYTE)malloc(oh->SectionAlignment);
	ZeroMemory(rawData, oh->SectionAlignment);
	memcpy(rawData, newData, size);
	memcpy(rawData + size - 1, pushAsm, sizeof(pushAsm));
	memcpy(rawData + size + sizeof(pushAsm) - 2, hexOep, sizeof(hexOep));
	memcpy(rawData + size + sizeof(pushAsm) + sizeof(hexOep) - 2, espReg, sizeof(espReg));
	WriteFile(FileHandle, rawData, oh->SectionAlignment, 0, nullptr);
	delete rawData;
	delete peCopy;
	CloseHandle(FileHandle);
}
/*
inline void PEHandler::RunOnMemory(HMODULE hMod, LPWSTR iProcCmd = nullptr, DWORD* lErr)
{
	LPWSTR exeName = nullptr;
	STARTUPINFO sInfo;
	PROCESS_INFORMATION procInfo;
	LPCONTEXT ptContext = nullptr;
	LPVOID rpImageBase;
	LPVOID ibPointer;
	if (GetModuleFileName(hMod, exeName, MAX_PATH) == 0)
	{
		*lErr = GetLastError();
		return;
	}
	memset(&sInfo, 0, sizeof(STARTUPINFO));
	memset(&procInfo, 0, sizeof(PROCESS_INFORMATION));
	if (!CreateProcess(exeName, iProcCmd, 0, 0, FALSE, CREATE_SUSPENDED, 0, 0, &sInfo, &procInfo))
	{
		*lErr = GetLastError();
		return;
	}

	ptContext = (CONTEXT*)VirtualAlloc(0, sizeof(CONTEXT), MEM_COMMIT, PAGE_READWRITE);
	ptContext->ContextFlags = CONTEXT_FULL;

	if (!GetThreadContext(procInfo.hThread, ptContext))
	{
		*lErr = GetLastError();
		return;
	}

	if (!ReadProcessMemory(procInfo.hProcess, (LPCVOID)(ptContext->Ebx + 8), rpImageBase, sizeof(LPVOID), 0)) {
		*lErr = GetLastError();
		return;
	}


	typedef LONG(__stdcall* PtrNtUnmapViewOfSection)(HANDLE, LPVOID);
	PtrNtUnmapViewOfSection NtUnmapViewOfSection = (PtrNtUnmapViewOfSection)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtUnmapViewOfSection");
	NtUnmapViewOfSection(procInfo.hProcess, rpImageBase);

	if (!(ibPointer = VirtualAllocEx(procInfo.hProcess, (LPVOID)this->NtHeaders.OptionalHeader.ImageBase, this->NtHeaders.OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE))) {
		*lErr = GetLastError();
		return;
	}


}*/


PEHandler::~PEHandler()
{
	UnmapViewOfFile(MapView);
	CloseHandle(MappingHandle);
	if (FileHandle != INVALID_HANDLE_VALUE)
		CloseHandle(FileHandle);
}
