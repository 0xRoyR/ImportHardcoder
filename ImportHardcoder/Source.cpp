#include <iostream>
#include <stdio.h>
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

int main() {
	LPCSTR fileName = "C:\\Users\\Roy\\Desktop\\SimpleEXE.exe";
	HANDLE hFile = CreateFileA(fileName, GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		cout << "[-] Error opening " << fileName << ". Quitting." << endl;
		return 0;
	}
	cout << "[+] Opened " << fileName << ". Handle Address: 0x" << hFile << endl;

	HANDLE hFileMappingObject = CreateFileMappingA(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
	if (hFileMappingObject == NULL) {
		cout << GetLastError() << endl;
		cout << "[-] Error getting handle to file mapping object. Quitting." << endl;
		return 0;
	}
	cout << "[+] Got handle to file mapping object: 0x" << hFileMappingObject << endl;

	LPVOID view = MapViewOfFileEx(hFileMappingObject, FILE_MAP_ALL_ACCESS, 0, 0, 0, NULL);
	if (view == NULL) {
		cout << "[-] Fialed to map the file to memory. Quitting." << endl;
		return 0;
	}
	cout << "[+] Mapped the file to memory at: 0x" << view << endl;

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
		cout << "oooops" << endl;
		return 0;
	}
	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
		sectionHeaders[i] = (PIMAGE_SECTION_HEADER)((PBYTE)optionalHeader + ntHeaders->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_SECTION_HEADER) * i);
		cout << "This is the section header of section '" << sectionHeaders[i]->Name << "'." << "Start of raw data: 0x" << (PDWORD)((PBYTE)view + Rva2Offset(sectionHeaders[i]->VirtualAddress, sectionHeaders[0], ntHeaders)) << endl;
	}


	/*
	PIMAGE_IMPORT_DESCRIPTOR importDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)view + dataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	cout << "Address of data directory: 0x" << dataDirectory << endl;
	cout << "Address of import directory: 0x" << importDirectory << endl;
	
	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections - 1; i++) {
		if ((PDWORD)importDirectory >= (PDWORD)((PBYTE)view + sectionHeaders[i]->VirtualAddress) && (PDWORD)importDirectory < (PDWORD)((PBYTE)view + sectionHeaders[i + 1]->VirtualAddress)) {
			cout << "The import directory is in the '" << sectionHeaders[i]->Name << "' section" << endl;
			break;
		}
	}

	PIMAGE_IMPORT_DESCRIPTOR firstImport = importDirectory;
	while (firstImport->FirstThunk) {
		cout << "current import: " << firstImport->Name << endl;
		cout << "current import name should be at: 0x" << (PVOID)((char*)view + firstImport->Name) << endl;
		cout << "ttt: " << (char*)view + Rva2Offset(firstImport->Name, sectionHeaders[0], ntHeaders);
		firstImport = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)firstImport + sizeof(IMAGE_IMPORT_DESCRIPTOR));
	}
	*/

	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor;
	if (dataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0) {
		cout << "No import table. Quitting." << endl;
		return 0;
	}

	pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)view + Rva2Offset(dataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, sectionHeaders[0], ntHeaders));
	PIMAGE_IMPORT_DESCRIPTOR pCurrImportDescriptor = pImportDescriptor;

	cout << "-----" << endl;
	int indexOfSectionContainingImportTable = -1;
	PBYTE pStartOfNextSection = 0x0;
	PBYTE pEndOfLastSection = 0x0;
	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections - 1; i++) {
		if ((PBYTE)pImportDescriptor >= (PBYTE)view + Rva2Offset(sectionHeaders[i]->VirtualAddress, sectionHeaders[0], ntHeaders) && (PBYTE)pImportDescriptor < (PBYTE)view + Rva2Offset(sectionHeaders[i + 1]->VirtualAddress, sectionHeaders[0], ntHeaders)) {
			cout << "The import directory is in the '" << sectionHeaders[i]->Name << "' section" << endl;
			cout << "VirtualAddress of this section: 0x" << (DWORD)((PBYTE)view + sectionHeaders[i]->VirtualAddress) << endl;
			cout << "VirtualSize of this section: " << sectionHeaders[i]->Misc.VirtualSize << endl;
			cout << "SizeOfRawData of this section: " << sectionHeaders[i]->SizeOfRawData << endl;
			cout << endl;
			indexOfSectionContainingImportTable = i;
			pStartOfNextSection = (PBYTE)view + sectionHeaders[i]->PointerToRawData + sectionHeaders[i]->SizeOfRawData;
			break;
		}
	}
	pEndOfLastSection = (PBYTE)view + sectionHeaders[ntHeaders->FileHeader.NumberOfSections - 1]->PointerToRawData + sectionHeaders[ntHeaders->FileHeader.NumberOfSections - 1]->SizeOfRawData;
	if (indexOfSectionContainingImportTable == -1) {
		cout << "The import directory is in the '" << sectionHeaders[ntHeaders->FileHeader.NumberOfSections - 1]->Name << "' section" << endl;
		indexOfSectionContainingImportTable = ntHeaders->FileHeader.NumberOfSections - 1;
		pStartOfNextSection = pEndOfLastSection;
	}


	// TODO
	// 1. Check the size of PIMAGE_IMPORT_DESCRIPTOR Value
	// 2. Check if the last sizeof(IMAGE_IMPORT_DESCRIPTOR) bytes of the target section are all 0
	// 3. If they do, insert there our new IMAGE_IMPORT_DESCRIPTOR value.
	// 4. If they don't, or if you wanna do it less the arab way and more the good way, increase the target section by sizeof(IMAGE_IMPORT_DESCRIPTOR) bytes, put our struct in the right place, and move all the data in the section from that address sizeof(IMAGE_IMPORT_DESCRIPTOR) bytes forward


	PBYTE t = (PBYTE)calloc(sizeof(IMAGE_IMPORT_DESCRIPTOR), 1);
	PBYTE pLastBytesOfTargetSection = (PBYTE)pStartOfNextSection - sizeof(IMAGE_IMPORT_DESCRIPTOR);
	cout << "lets see: 0x" << (PDWORD)pLastBytesOfTargetSection << endl;
	if (!memcmp(pLastBytesOfTargetSection, t, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
		cout << "HEYY" << endl;
	}

	while (pCurrImportDescriptor->Name != NULL) {
		//cout << "Curr import: " << (char*)view + Rva2Offset(pCurrImportDescriptor->Name, sectionHeaders[0], ntHeaders) << endl;
		printf("Curr Address: 0x%p\n", (char*)view + Rva2Offset(pCurrImportDescriptor->Name, sectionHeaders[0], ntHeaders));
		pCurrImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)pCurrImportDescriptor + sizeof(IMAGE_IMPORT_DESCRIPTOR));
		cout << "Curr OriginalFirstThunk: " << pCurrImportDescriptor->OriginalFirstThunk << endl;
		cout << "Curr TimeDateStamp: " << pCurrImportDescriptor->TimeDateStamp << endl;
		cout << "Curr ForwarderChain: " << pCurrImportDescriptor->ForwarderChain << endl;
		cout << "Curr Name: " << (char*)view + Rva2Offset(pCurrImportDescriptor->Name, sectionHeaders[0], ntHeaders) << endl;
		cout << "Curr FirstThunk: " << pCurrImportDescriptor->FirstThunk << endl;
		cout << endl;
	}
	//(PBYTE)view + sectionHeaders[ntHeaders->FileHeader.NumberOfSections - 1]->PointerToRawData + sectionHeaders[ntHeaders->FileHeader.NumberOfSections - 1]->SizeOfRawData;
	sectionHeaders[ntHeaders->FileHeader.NumberOfSections - 1]->SizeOfRawData += optionalHeader->FileAlignment;
	sectionHeaders[ntHeaders->FileHeader.NumberOfSections - 1]->Misc.VirtualSize += optionalHeader->FileAlignment;


	return 0;

}