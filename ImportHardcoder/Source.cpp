#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>

using namespace std;

/*Convert Virtual Address to File Offset */
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

DWORD Offset2Rva(DWORD offset, PIMAGE_SECTION_HEADER psh, PIMAGE_NT_HEADERS pnt) {
	size_t i = 0;
	PIMAGE_SECTION_HEADER pSeh;
	if (offset == 0) {
		return offset;
	}
	pSeh = psh;
	for (i = 0; i < pnt->FileHeader.NumberOfSections; i++) {
		if (offset >= pSeh->PointerToRawData && offset < pSeh->PointerToRawData + pSeh->SizeOfRawData) {
			return offset - pSeh->PointerToRawData + pSeh->VirtualAddress;
		}
		pSeh++;
	}
	return offset - pSeh->PointerToRawData + pSeh->VirtualAddress;
}

int main() {
	LPCSTR fileName = "C:\\Users\\Roy\\Desktop\\SimpleEXE.exe";
	LPCSTR dllName = "dllName";
	LPCSTR dstFile = "C:\\Users\\Roy\\Desktop\\res.exe";

	HANDLE hFile = CreateFileA(fileName, GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		cout << "[-] Error opening " << fileName << ". Quitting." << endl;
		return 0;
	}
	
	DWORD fileSize = GetFileSize(hFile, NULL);
	if (fileSize == INVALID_FILE_SIZE) {
		cout << " [-] Error getting file size of " << fileName << ". Quitting" << endl;
		return 0;
	}
	cout << "[+] Opened " << fileName << ". Handle Address: 0x" << hFile << ". File size: " << fileSize << endl;

	LPVOID view = (LPVOID)malloc(fileSize);
	if (ReadFile(hFile, view, fileSize, NULL, NULL) == NULL) {
		cout << "[-] Unable to read " << fileName << " to memory. Quitting." << endl;
	}
	cout << "[+] Read " << fileName << " to memory at: 0x" << view << endl;

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)view;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		cout << "[-] Invalid DOS Signature. Quitting" << endl;
		return 0;
	}
	PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((PBYTE)view + dosHeader->e_lfanew);
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
		cout << "[-] Invalid ntHeaders Signature. Quitting." << endl;
		return 0;
	}
	PIMAGE_OPTIONAL_HEADER64 optionalHeader = (PIMAGE_OPTIONAL_HEADER64)&ntHeaders->OptionalHeader;

	PIMAGE_DATA_DIRECTORY dataDirectory = (PIMAGE_DATA_DIRECTORY)(optionalHeader->DataDirectory);
	PIMAGE_SECTION_HEADER* sectionHeaders = (PIMAGE_SECTION_HEADER*)malloc(ntHeaders->FileHeader.NumberOfSections * sizeof(PIMAGE_SECTION_HEADER));
	if (sectionHeaders == NULL) {
		//cout << "oooops" << endl;
		return 0;
	}
	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
		sectionHeaders[i] = (PIMAGE_SECTION_HEADER)((PBYTE)optionalHeader + ntHeaders->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_SECTION_HEADER) * i);
		//cout << "This is the section header of section '" << sectionHeaders[i]->Name << "'." << "Start of raw data: 0x" << (PDWORD)((PBYTE)view + Rva2Offset(sectionHeaders[i]->VirtualAddress, sectionHeaders[0], ntHeaders)) << endl;
	}

	PIMAGE_IMPORT_DESCRIPTOR pFirstImportDescriptor;
	if (dataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0) {
		cout << "No import table. Quitting." << endl;
		return 0;
	}

	pFirstImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)view + Rva2Offset(dataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, sectionHeaders[0], ntHeaders));
	PIMAGE_IMPORT_DESCRIPTOR* pImportDescriptors = (PIMAGE_IMPORT_DESCRIPTOR*)malloc(sizeof(PIMAGE_IMPORT_DESCRIPTOR));
	PIMAGE_IMPORT_DESCRIPTOR pCurrImportDescriptor = pFirstImportDescriptor;
	int numberOfImageImportDescriptors = 0;
	while (pCurrImportDescriptor->Name != NULL) {
		pImportDescriptors = (PIMAGE_IMPORT_DESCRIPTOR*)realloc(pImportDescriptors, sizeof(PIMAGE_IMPORT_DESCRIPTOR) * (numberOfImageImportDescriptors + 1));
		pImportDescriptors[numberOfImageImportDescriptors] = (PIMAGE_IMPORT_DESCRIPTOR)malloc(sizeof(IMAGE_IMPORT_DESCRIPTOR));
		if (!memcpy(pImportDescriptors[numberOfImageImportDescriptors], pCurrImportDescriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
			cout << "[-] There was an error copying the image import descriptor at index " << numberOfImageImportDescriptors << ". Quitting." << endl;
			return 0;
		}
		pCurrImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)pCurrImportDescriptor + sizeof(IMAGE_IMPORT_DESCRIPTOR));
		
		printf("Curr Address: 0x%p\n", (char*)view + Rva2Offset(pImportDescriptors[numberOfImageImportDescriptors]->Name, sectionHeaders[0], ntHeaders));
		cout << "Curr OriginalFirstThunk: " << pImportDescriptors[numberOfImageImportDescriptors]->OriginalFirstThunk << endl;
		cout << "Curr TimeDateStamp: " << pImportDescriptors[numberOfImageImportDescriptors]->TimeDateStamp << endl;
		cout << "Curr ForwarderChain: " << pImportDescriptors[numberOfImageImportDescriptors]->ForwarderChain << endl;
		cout << "Curr Name: " << (char*)view + Rva2Offset(pImportDescriptors[numberOfImageImportDescriptors]->Name, sectionHeaders[0], ntHeaders) << endl;
		cout << "Curr FirstThunk: " << pImportDescriptors[numberOfImageImportDescriptors]->FirstThunk << endl;
		cout << endl;
		
		numberOfImageImportDescriptors++;
	}

	
	int indexOfSectionContainingImportTable = -1;
	PBYTE pStartOfNextSection_FullAddress = 0x0;
	PBYTE pEndOfLastSection_FullAddress = 0x0;
	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections - 1; i++) {
		if ((PBYTE)pFirstImportDescriptor >= (PBYTE)view + Rva2Offset(sectionHeaders[i]->VirtualAddress, sectionHeaders[0], ntHeaders) && (PBYTE)pFirstImportDescriptor < (PBYTE)view + Rva2Offset(sectionHeaders[i + 1]->VirtualAddress, sectionHeaders[0], ntHeaders)) {
			cout << "[???] [Do we even need this part?] The import directory is in the '" << sectionHeaders[i]->Name << "' section" << endl;
			cout << "VirtualAddress of this section: 0x" << (DWORD)((PBYTE)view + sectionHeaders[i]->VirtualAddress) << endl;
			cout << "VirtualSize of this section: " << sectionHeaders[i]->Misc.VirtualSize << endl;
			cout << "SizeOfRawData of this section: " << sectionHeaders[i]->SizeOfRawData << endl;
			cout << endl;
			indexOfSectionContainingImportTable = i;
			pStartOfNextSection_FullAddress = (PBYTE)view + sectionHeaders[i]->PointerToRawData + sectionHeaders[i]->SizeOfRawData;
			break;
		}
	}
	pEndOfLastSection_FullAddress = (PBYTE)view + sectionHeaders[ntHeaders->FileHeader.NumberOfSections - 1]->PointerToRawData + sectionHeaders[ntHeaders->FileHeader.NumberOfSections - 1]->SizeOfRawData;
	if (indexOfSectionContainingImportTable == -1) {
		cout << "[???] [Do we even need this part?] The import directory is in the '" << sectionHeaders[ntHeaders->FileHeader.NumberOfSections - 1]->Name << "' section" << endl;
		indexOfSectionContainingImportTable = ntHeaders->FileHeader.NumberOfSections - 1;
		pStartOfNextSection_FullAddress = pEndOfLastSection_FullAddress;
	}
	

	// Get the RVA of the end of the executable. This will use us later.
	DWORD endOfLastSection_VirtualAddress = sectionHeaders[ntHeaders->FileHeader.NumberOfSections - 1]->VirtualAddress + sectionHeaders[ntHeaders->FileHeader.NumberOfSections - 1]->SizeOfRawData;

	// Create new import lookup table for our dll
	IMAGE_THUNK_DATA64 newImportLookupTable[2];
	newImportLookupTable[0].u1.Ordinal = 0x8000000000000001;
	newImportLookupTable[1].u1.Ordinal = 0;
	 
	// Determine the size to append to the last section.
	DWORD totalAdditionalSize = numberOfImageImportDescriptors * sizeof(IMAGE_IMPORT_DESCRIPTOR) + 2 * sizeof(IMAGE_THUNK_DATA64) + strlen(dllName) + 1;
	DWORD sizeToAppend = 0;
	do {
		sizeToAppend += optionalHeader->FileAlignment;
	} while (sizeToAppend < totalAdditionalSize);
	cout << "Additional size that we need: " << totalAdditionalSize << endl;
	cout << "File Alignment: " << optionalHeader->FileAlignment << endl;
	cout << "Total size that will be added: " << sizeToAppend << endl;

	// Add 'sizeToAppend' to the last section's size
	sectionHeaders[ntHeaders->FileHeader.NumberOfSections - 1]->SizeOfRawData += sizeToAppend;
	sectionHeaders[ntHeaders->FileHeader.NumberOfSections - 1]->Misc.VirtualSize += sizeToAppend;

	// The last section must have read/write permissions at minimum to allow the loader to store the resolved IAT value
	sectionHeaders[ntHeaders->FileHeader.NumberOfSections - 1]->Characteristics |= IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

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

	// Set the Image Data Directory pointer to point the new image import descriptors array
	dataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = endOfLastSection_VirtualAddress;
	dataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = numberOfImageImportDescriptors * sizeof(IMAGE_IMPORT_DESCRIPTOR);

	// Allocate new view
	DWORD newFileSize = fileSize + sizeToAppend;
	LPVOID newView = (LPVOID)malloc(newFileSize);
	if (newView == NULL) {
		cout << "[-] Error reallocating the memory of the original file. Quitting." << endl;
		return 0;
	}
	// Copy the original view into the new view
	if (!memcpy(newView, view, fileSize)) {
		cout << "[-] Error copying the executable to the new view. Quitting" << endl;
		return 0;
	}
	cout << "[+] Copied the executable to the new view" << endl;

	// Copy the new image import descriptors into the new view (after the end of the original executable)
	for (int i = 0; i < numberOfImageImportDescriptors; i++) {
		if (!memcpy((PBYTE)newView + fileSize + i * sizeof(IMAGE_IMPORT_DESCRIPTOR), pImportDescriptors[i], sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
			cout << "[-] Error copying the new import descriptors array at index " << i << ". Quitting." << endl;
			return 0;
		}
	}
	cout << "[+] Copied the new import descriptors array to the new view (at the end of the original executable)" << endl;
	cout << "Total number of new image import descriptors: " << numberOfImageImportDescriptors << endl;

	// Copy our dll name into the new view (after the end of the new image import descriptors array)
	if (!memcpy((PBYTE)newView + fileSize + numberOfImageImportDescriptors * sizeof(IMAGE_IMPORT_DESCRIPTOR), dllName, strlen(dllName) + 1)) {
		cout << "[-] Error copying the dll name to the new view. Quitting" << endl;
		return 0;
	}
	cout << "[+] Copied the dll name to the new view (at the end of the new image import descriptors array)" << endl;

	// Copy our IMAGE_THUNK_DATA64 array into the new view (after the end of the dll name)
	if (!memcpy((PBYTE)newView + fileSize + numberOfImageImportDescriptors * sizeof(IMAGE_IMPORT_DESCRIPTOR) + strlen(dllName) + 1, newImportLookupTable, sizeof(IMAGE_THUNK_DATA64) * 2)) {
		cout << "[-] Error copying IMAGE_THUNK_DATA64 array name to the new view. Quitting" << endl;
		return 0;
	}
	cout << "[+] Copied the IMAGE_THUNK_DATA64 array to the new view (at the end of the dll name)" << endl;

	HANDLE hOutFile = CreateFileA(dstFile, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		cout << "[-] Error creating " << fileName << ". Quitting." << endl;
		return 0;
	}
	if (WriteFile(hOutFile, newView, newFileSize, NULL, NULL) == NULL) {
		cout << "[-] Error writing the modified exe to the destination file (" << dstFile << "). Quitting." << endl;
	}
	cout << "[+] succseully modified exe to the destination file (" << dstFile << "). Quitting." << endl;

	return 0;
}