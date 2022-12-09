#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <stdint.h>

/* Good Ressources :
*  https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/pe-file-header-parser-in-c++
*  https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
*
*/

int main(void) {

	printf("Starting Loader...\n");

	//-------Read Executable to buffer-------
	//target.exe is x64
	LPCWSTR file_path = L"D:\\C-Programming\\x64\\Debug\\target.exe";
	printf("File Path: %ws\n", file_path);

	HANDLE hFile = CreateFileW(file_path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		printf("%d\n", GetLastError());


	DWORD fileSize = GetFileSize(hFile, NULL);
	LPVOID fileData = HeapAlloc(GetProcessHeap(), 0, fileSize);
	BOOL status = ReadFile(hFile, fileData, fileSize, NULL, NULL);

	if (status == FALSE)
		printf("%d\n", GetLastError());

	CloseHandle(hFile);

	printf("Read executable into Buffer\n");

	//-------Signature Check-------
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileData;
	PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((BYTE*)fileData + dosHeader->e_lfanew);

	if (imageNTHeaders->Signature != IMAGE_NT_SIGNATURE) {
		printf("Image is not an executable... I can only load executables\n");
		return EXIT_FAILURE;
	}

	printf("PE File format detected\n");

	//-------^COFF File Header^ Machine Type Check-------
	if (imageNTHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
		(imageNTHeaders->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) != IMAGE_FILE_EXECUTABLE_IMAGE) {
		printf("Unsupported Machine Type\n");
		return EXIT_FAILURE;
	}	

	//-------^Optional Header^-------
	printf("Optional Header Magic: 0x%x\n", imageNTHeaders->OptionalHeader.Magic);
	printf("image_base: 0x%x\n", imageNTHeaders->OptionalHeader.ImageBase);
	

	//-------^Section Header^-------
	uintptr_t sectionLocation = (uintptr_t)imageNTHeaders + sizeof(DWORD) + (uintptr_t)(sizeof(IMAGE_FILE_HEADER)) + (uintptr_t)imageNTHeaders->FileHeader.SizeOfOptionalHeader;
	DWORD sectionSize = (DWORD)sizeof(IMAGE_SECTION_HEADER);
	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(imageNTHeaders);

	DWORD image_buf = imageNTHeaders->OptionalHeader.SizeOfImage;
	UINT* image_base = (UINT) & image_buf;
	
	//Allocate Memory for the loaded executable if we can't aloocate the pref. base addr we chose a random one.
	LPVOID baseAddr = VirtualAlloc(imageNTHeaders->OptionalHeader.ImageBase, imageNTHeaders->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!baseAddr) {
		baseAddr = VirtualAlloc(0, imageNTHeaders->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	}

	//Copy Headers
	memcpy(baseAddr, fileData, imageNTHeaders->OptionalHeader.SizeOfHeaders);

	printf("Allocated buffer of size 0x%x\n", image_buf);

	//Copy the scetions
	for (int i = 0; i < imageNTHeaders->FileHeader.NumberOfSections; i++) {
		sectionHeader = (PIMAGE_SECTION_HEADER)sectionLocation;
		printf("Section name: %s\n", sectionHeader->Name);
		printf("Virtual Address: 0x%x\n", sectionHeader->VirtualAddress);
		memcpy((char*)baseAddr + sectionHeader->VirtualAddress,(char *)fileData + sectionHeader->PointerToRawData, sectionHeader->SizeOfRawData);
		sectionLocation += sectionSize;
	}

	//Calculate entry point
	LPVOID entry = (uintptr_t)baseAddr + imageNTHeaders->OptionalHeader.AddressOfEntryPoint;
	int (*ptrmain)(int) = (int (*)(int))(entry);

	//Call entry point with the value we got from Reverse engineering the target binary. 5 == failed, 1 == success
	int a = ptrmain(0x13371337);
	printf("Returned: %d", a);

	return EXIT_SUCCESS;
}
