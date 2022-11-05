#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>

using namespace std;


DWORD Rva2Offset(DWORD rva, PIMAGE_SECTION_HEADER psh, PIMAGE_NT_HEADERS pnt)
{
	size_t i = 0;
	PIMAGE_SECTION_HEADER pSeh;
	if (rva == 0)
	{
		return (rva);
	}
	pSeh = psh;
	for (i = 0; i < pnt->FileHeader.NumberOfSections; i++)
	{
		if (rva >= pSeh->VirtualAddress && rva < pSeh->VirtualAddress +
			pSeh->Misc.VirtualSize)
		{
			break;
		}
		pSeh++;
	}
	return (rva - pSeh->VirtualAddress + pSeh->PointerToRawData);
}

int main(int argc, char *argv[]) {
	if (argc < 4) {
		cout << "[-] Provided too few arguments. Quitting." << endl;
		return 0;
	}
	LPCSTR inFile = argv[1]; // Path to the input exe file
	LPCSTR dllName = argv[2]; // The name of the dll
	LPCSTR outFile = argv[3]; // Path to the output exe file

	HANDLE hFile = CreateFileA(inFile, GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		cout << "[-] Error opening " << inFile << ". Quitting." << endl;
		return 0;
	}
	
	DWORD fileSize = GetFileSize(hFile, NULL);
	if (fileSize == INVALID_FILE_SIZE) {
		cout << " [-] Error getting file size of " << inFile << ". Quitting" << endl;
		return 0;
	}
	cout << "[+] Opened " << inFile << ". Handle Address: 0x" << hFile << ". File size: " << fileSize << " bytes." << endl;

	LPVOID view = (LPVOID)malloc(fileSize);
	if (ReadFile(hFile, view, fileSize, NULL, NULL) == NULL) {
		cout << "[-] Unable to read " << inFile << " to memory. Quitting." << endl;
	}
	cout << "[+] Mapped " << inFile << " to memory at: 0x" << view << endl;

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)view;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		cout << "[-] Invalid DOS Signature. Quitting" << endl;
		return 0;
	}
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PBYTE)view + dosHeader->e_lfanew);
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
		cout << "[-] Invalid ntHeaders Signature. Quitting." << endl;
		return 0;
	}

	PIMAGE_OPTIONAL_HEADER optionalHeader = (PIMAGE_OPTIONAL_HEADER)&ntHeaders->OptionalHeader;
	PIMAGE_DATA_DIRECTORY dataDirectory = (PIMAGE_DATA_DIRECTORY)(optionalHeader->DataDirectory);
	PIMAGE_SECTION_HEADER* sectionHeaders = (PIMAGE_SECTION_HEADER*)malloc(ntHeaders->FileHeader.NumberOfSections * sizeof(PIMAGE_SECTION_HEADER));
	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
		sectionHeaders[i] = (PIMAGE_SECTION_HEADER)((PBYTE)optionalHeader + ntHeaders->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_SECTION_HEADER) * i);
	}
	cout << "[+] Read section headers." << endl;

	IMAGE_DATA_DIRECTORY ttt = dataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (ttt.Size == 0) {
		cout << "[?] No import table. Quitting." << endl;
		cout << "Virtual Address of Data Directory: 0x" << dataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress << endl;
		return 0;
	}

	PIMAGE_IMPORT_DESCRIPTOR pFirstImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)view + Rva2Offset(dataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, sectionHeaders[0], ntHeaders));
	PIMAGE_IMPORT_DESCRIPTOR* pImportDescriptors = (PIMAGE_IMPORT_DESCRIPTOR*)malloc(sizeof(PIMAGE_IMPORT_DESCRIPTOR));
	PIMAGE_IMPORT_DESCRIPTOR pCurrImportDescriptor = pFirstImportDescriptor;
	int numberOfImageImportDescriptors = 0;
	while (pCurrImportDescriptor->Name != NULL) {
		pImportDescriptors = (PIMAGE_IMPORT_DESCRIPTOR*)realloc(pImportDescriptors, sizeof(PIMAGE_IMPORT_DESCRIPTOR) * (numberOfImageImportDescriptors + 1));
		pImportDescriptors[numberOfImageImportDescriptors] = (PIMAGE_IMPORT_DESCRIPTOR)malloc(sizeof(IMAGE_IMPORT_DESCRIPTOR));
		if (!memcpy(pImportDescriptors[numberOfImageImportDescriptors], pCurrImportDescriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
			cout << "[-] Error copying the image import descriptor at index " << numberOfImageImportDescriptors << ". Quitting." << endl;
			return 0;
		}
		pCurrImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)pCurrImportDescriptor + sizeof(IMAGE_IMPORT_DESCRIPTOR));
		numberOfImageImportDescriptors++;
	}
	cout << "[+] Copied the original image import descriptors array." << endl;

	// Get the RVA of the end of the executable. This will use us later.
	DWORD endOfLastSection_VirtualAddress = sectionHeaders[ntHeaders->FileHeader.NumberOfSections - 1]->VirtualAddress + sectionHeaders[ntHeaders->FileHeader.NumberOfSections - 1]->SizeOfRawData;
	cout << "[+] Got the RVA of the end of the executable." << endl;

	// Create new import lookup table for our dll
	IMAGE_THUNK_DATA newImportLookupTable[2];
	newImportLookupTable[0].u1.Ordinal = 0x8000000000000001;
	newImportLookupTable[1].u1.Ordinal = 0;
	cout << "[+] Created new import lookup table." << endl;
	 
	// Determine the size to append to the last section.
	DWORD totalAdditionalSize = numberOfImageImportDescriptors * sizeof(IMAGE_IMPORT_DESCRIPTOR) + 2 * sizeof(IMAGE_THUNK_DATA) + strlen(dllName) + 1;
	DWORD sizeToAppend = 0;
	do {
		sizeToAppend += optionalHeader->FileAlignment;
	} while (sizeToAppend < totalAdditionalSize);

	// Add 'sizeToAppend' to the last section's size
	sectionHeaders[ntHeaders->FileHeader.NumberOfSections - 1]->SizeOfRawData += sizeToAppend;
	sectionHeaders[ntHeaders->FileHeader.NumberOfSections - 1]->Misc.VirtualSize += sizeToAppend;
	cout << "[+] Appended the size of the last section by " << sizeToAppend << " bytes." << endl;

	// The last section must have read/write permissions at minimum to allow the loader to store the resolved IAT value
	sectionHeaders[ntHeaders->FileHeader.NumberOfSections - 1]->Characteristics |= IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
	cout << "[+] Added Read/Write permissions to the last section." << endl;

	// Allocate memory to 2 more Image Import Descriptors in our new array
	pImportDescriptors = (PIMAGE_IMPORT_DESCRIPTOR*)realloc(pImportDescriptors, sizeof(PIMAGE_IMPORT_DESCRIPTOR) * (numberOfImageImportDescriptors + 2));
	numberOfImageImportDescriptors += 2;
	PIMAGE_IMPORT_DESCRIPTOR ourOwnImportDescriptor;
	// Place the descriptor of our own dll in the second last import descriptor of the array
	pImportDescriptors[numberOfImageImportDescriptors - 2] = (PIMAGE_IMPORT_DESCRIPTOR)malloc(sizeof(IMAGE_IMPORT_DESCRIPTOR));
	pImportDescriptors[numberOfImageImportDescriptors - 2]->Name = endOfLastSection_VirtualAddress + numberOfImageImportDescriptors * sizeof(IMAGE_IMPORT_DESCRIPTOR);
	pImportDescriptors[numberOfImageImportDescriptors - 2]->OriginalFirstThunk = pImportDescriptors[numberOfImageImportDescriptors - 2]->Name + strlen(dllName) + 1;
	pImportDescriptors[numberOfImageImportDescriptors - 2]->FirstThunk = pImportDescriptors[numberOfImageImportDescriptors - 2]->OriginalFirstThunk;
	pImportDescriptors[numberOfImageImportDescriptors - 2]->Characteristics = 0;
	pImportDescriptors[numberOfImageImportDescriptors - 2]->ForwarderChain = 0;
	pImportDescriptors[numberOfImageImportDescriptors - 2]->TimeDateStamp = 0;
	// Place the terminating descriptor at the last import descriptor of the array
	pImportDescriptors[numberOfImageImportDescriptors - 1] = (PIMAGE_IMPORT_DESCRIPTOR)malloc(sizeof(IMAGE_IMPORT_DESCRIPTOR));
	pImportDescriptors[numberOfImageImportDescriptors - 1]->Characteristics = 0;
	pImportDescriptors[numberOfImageImportDescriptors - 1]->FirstThunk = 0;
	pImportDescriptors[numberOfImageImportDescriptors - 1]->ForwarderChain = 0;
	pImportDescriptors[numberOfImageImportDescriptors - 1]->Name = 0;
	pImportDescriptors[numberOfImageImportDescriptors - 1]->OriginalFirstThunk = 0;
	pImportDescriptors[numberOfImageImportDescriptors - 1]->TimeDateStamp = 0;
	cout << "[+] Added 2 Image Import Descriptors to the image import descriptors array." << endl;

	// Set the Image Data Directory pointer to point the new image import descriptors array
	dataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = endOfLastSection_VirtualAddress;
	dataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = numberOfImageImportDescriptors * sizeof(IMAGE_IMPORT_DESCRIPTOR);
	cout << "[+] Image Data Directory now points to the new image import descriptors array." << endl;

	// Reallocate view to be able to store the new image import descriptors array, dll name and the IMAGE_THUNK_DATA array
	DWORD newFileSize = fileSize + sizeToAppend;
	view = (LPVOID)realloc(view, newFileSize);
	if (view == NULL) {
		cout << "[-] Error reallocating the memory of the original file. Quitting." << endl;
		return 0;
	}

	// Copy the new image import descriptors to after the end of the original executable
	for (int i = 0; i < numberOfImageImportDescriptors; i++) {
		if (!memcpy((PBYTE)view + fileSize + i * sizeof(IMAGE_IMPORT_DESCRIPTOR), pImportDescriptors[i], sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
			cout << "[-] Error copying the new import descriptors array at index " << i << ". Quitting." << endl;
			return 0;
		}
	}

	// Copy our dll name to after the end of the new image import descriptors array
	if (!memcpy((PBYTE)view + fileSize + numberOfImageImportDescriptors * sizeof(IMAGE_IMPORT_DESCRIPTOR), dllName, strlen(dllName) + 1)) {
		cout << "[-] Error copying the dll name. Quitting." << endl;
		return 0;
	}
	cout << "[+] Copied the dll name (at the end of the new image import descriptors array)." << endl;

	// Copy our IMAGE_THUNK_DATA array to after the end of the dll name
	if (!memcpy((PBYTE)view + fileSize + numberOfImageImportDescriptors * sizeof(IMAGE_IMPORT_DESCRIPTOR) + strlen(dllName) + 1, newImportLookupTable, sizeof(IMAGE_THUNK_DATA) * 2)) {
		cout << "[-] Error copying IMAGE_THUNK_DATA array. Quitting." << endl;
		return 0;
	}
	cout << "[+] Copied the IMAGE_THUNK_DATA array (at the end of the dll name)." << endl;

	HANDLE hOutFile = CreateFileA(outFile, GENERIC_ALL, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		cout << "[-] Error creating " << inFile << ". Quitting." << endl;
		return 0;
	}
	else if (GetLastError() == ERROR_FILE_EXISTS) {
		cout << "[-] " << inFile << " already exists. Quitting." << endl;
		return 0;
	}
	if (WriteFile(hOutFile, view, newFileSize, NULL, NULL) == NULL) {
		cout << "[-] Error writing the modified exe to the destination file (" << outFile << "). Quitting." << endl;
	}
	cout << "[+] succseully added '" << dllName << "' dependency to " << inFile << "." << endl;
	cout << "Output File: " << outFile << endl;

	return 0;
}