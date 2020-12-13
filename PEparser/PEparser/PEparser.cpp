#include <Windows.h>
#include <iostream>

using namespace std;
#pragma warning (disable:6031)
#pragma warning (disable:6011)
#pragma warning (disable:6066)
#pragma warning (disable:4133)
#pragma warning (disable:4477)
#pragma warning (disable:6067)

int main(int argc, char* argv[])
{
	printf("Detailed for https://docs.microsoft.com/zh-cn/windows/win32/debug/pe-format?redirectedfrom=MSDN \n\n");
	const int MAX_FILEPATH = 255;
	char fileName[MAX_FILEPATH] = "C:\\Windows\\SysWOW64\\notepad.exe";
	//char fileName[MAX_FILEPATH] = { 0 };
	//memcpy_s(&fileName, MAX_FILEPATH, argv[1], MAX_FILEPATH);

	//cout << fileName;
	PIMAGE_DOS_HEADER dosHeader = {};
	PIMAGE_NT_HEADERS32 imageNTHeaders = {};
	PIMAGE_SECTION_HEADER sectionHeader = {};
	PIMAGE_SECTION_HEADER exportSection = {};
	PIMAGE_SECTION_HEADER importSection = {};
	IMAGE_IMPORT_DESCRIPTOR* importDescriptor = {};
	PIMAGE_THUNK_DATA32 thunkData = {};

	HANDLE hFile = CreateFileA(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		printf("Counld not read file.");
	DWORD fileSize = GetFileSize(hFile, NULL);
	LPVOID fileData = HeapAlloc(GetProcessHeap(), 0, fileSize);

	ReadFile(hFile, fileData, fileSize, NULL, NULL);

	dosHeader = (PIMAGE_DOS_HEADER)fileData;
	imageNTHeaders = (PIMAGE_NT_HEADERS32)((DWORD)fileData + dosHeader->e_lfanew);

	if (dosHeader->e_magic != 0x5a4d && imageNTHeaders->Signature != 0x504500)
	{
		printf("It's an invalid PE file.");
		return 0;
	}

	// useful infomation in DOS header
	printf("************** DOS HEADER **************\n");
	printf("\t0x%p\t%X\t\tMagic number\n", &dosHeader->e_magic - fileData, dosHeader->e_magic);
	printf("\t0x%p\t%X\t\tFile address of new exe header\n", &dosHeader->e_lfanew - fileData, dosHeader->e_lfanew);

	// useful infomation in NT header
	printf("\n************** NT HEADERS **************\n");
	printf("\t0x%p\t%X\t\tSignature\n", (BYTE*)&imageNTHeaders->Signature - fileData, imageNTHeaders->Signature);
	// FILE_HEADER
	printf("\n************** FILE HEADER **************\n");
	printf("\t0x%p\t%X\t\tMachine\n", (BYTE*)&imageNTHeaders->FileHeader.Machine - fileData,
		imageNTHeaders->FileHeader.Machine);
	printf("\t0x%p\t%X\t\tNumber of Sections\n", (BYTE*)&imageNTHeaders->FileHeader.NumberOfSections - fileData,
		imageNTHeaders->FileHeader.NumberOfSections);
	printf("\t0x%p\t%X\t\tSize of Optional Header\n", (BYTE*)&imageNTHeaders->FileHeader.SizeOfOptionalHeader - fileData,
		imageNTHeaders->FileHeader.SizeOfOptionalHeader);
	printf("\t0x%p\t%X\t\tCharacteristics\n", (BYTE*)&imageNTHeaders->FileHeader.Characteristics - fileData,
		imageNTHeaders->FileHeader.Characteristics);

	// OPTIONAL_HEADER
	printf("\n************** OPTIONAL HEADER **************\n");
	printf("\t0x%p\t%X\t\tMagic\n", (BYTE*)&imageNTHeaders->OptionalHeader.Magic - fileData,
		imageNTHeaders->OptionalHeader.Magic);
	printf("\t0x%p\t%X\t\tSize Of Code\n", (BYTE*)&imageNTHeaders->OptionalHeader.SizeOfCode - fileData,
		imageNTHeaders->OptionalHeader.SizeOfCode);
	printf("\t0x%p\t%X\t\tSize Of Initialized Data\n", (BYTE*)&imageNTHeaders->OptionalHeader.SizeOfInitializedData - fileData,
		imageNTHeaders->OptionalHeader.SizeOfInitializedData);
	printf("\t0x%p\t%X\t\tSize Of UnInitialized Data\n", (BYTE*)&imageNTHeaders->OptionalHeader.SizeOfUninitializedData - fileData,
		imageNTHeaders->OptionalHeader.SizeOfUninitializedData);
	printf("\t0x%p\t%X\t\tAddress Of Entry Point (.text)\n", (BYTE*)&imageNTHeaders->OptionalHeader.AddressOfEntryPoint - fileData,
		imageNTHeaders->OptionalHeader.AddressOfEntryPoint);
	printf("\t0x%p\t%X\t\tBase Of Code\n", (BYTE*)&imageNTHeaders->OptionalHeader.BaseOfCode - fileData,
		imageNTHeaders->OptionalHeader.BaseOfCode);
	printf("\t0x%p\t%X\t\tImage Base\n", (BYTE*)&imageNTHeaders->OptionalHeader.ImageBase - fileData,
		imageNTHeaders->OptionalHeader.ImageBase);
	printf("\t0x%p\t%X\t\tSection Alignment\n", (BYTE*)&imageNTHeaders->OptionalHeader.SectionAlignment - fileData,
		imageNTHeaders->OptionalHeader.SectionAlignment);
	printf("\t0x%p\t%X\t\tFile Alignment\n", (BYTE*)&imageNTHeaders->OptionalHeader.FileAlignment - fileData,
		imageNTHeaders->OptionalHeader.FileAlignment);
	printf("\t0x%p\t%X\t\tSize Of Image\n", (BYTE*)&imageNTHeaders->OptionalHeader.SizeOfImage - fileData,
		imageNTHeaders->OptionalHeader.SizeOfImage);
	printf("\t0x%p\t%X\t\tSize Of Headers\n", (BYTE*)&imageNTHeaders->OptionalHeader.SizeOfHeaders - fileData,
		imageNTHeaders->OptionalHeader.SizeOfHeaders);
	printf("\t0x%p\t%X\t\tSubsystem\n", (BYTE*)&imageNTHeaders->OptionalHeader.Subsystem - fileData,
		imageNTHeaders->OptionalHeader.Subsystem);
	printf("\t0x%p\t%X\t\tDllCharacteristics\n", (BYTE*)&imageNTHeaders->OptionalHeader.DllCharacteristics - fileData,
		imageNTHeaders->OptionalHeader.DllCharacteristics);
	printf("\t0x%p\t%X\t\tNumber Of Rva And Sizes\n", (BYTE*)&imageNTHeaders->OptionalHeader.NumberOfRvaAndSizes - fileData,
		imageNTHeaders->OptionalHeader.NumberOfRvaAndSizes);

	printf("\n************** DATA DIRECTORIES **************\n");
	printf("\tExport Directory Address: 0x%08X (RVA); \tSize: 0x%x\n", imageNTHeaders->OptionalHeader.DataDirectory[0].VirtualAddress,
		imageNTHeaders->OptionalHeader.DataDirectory[0].Size);
	printf("\tImport Directory Address: 0x%08X (RVA); \tSize: 0x%x\n", imageNTHeaders->OptionalHeader.DataDirectory[1].VirtualAddress,
		imageNTHeaders->OptionalHeader.DataDirectory[1].Size);

	// SECTION_HEADERS 	
	printf("\n************** SECTION HEADERS **************\n");
	// get offset to first section headeer
	sectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)fileData + dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS32));

	DWORD importDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	DWORD exportDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	for (int i = 0; i < imageNTHeaders->FileHeader.NumberOfSections; i++)
	{
		printf("%s\n", sectionHeader->Name);
		printf("\t0x%p\t%X\t\tVirtual Size\n", (BYTE*)&sectionHeader->Misc.VirtualSize - fileData, sectionHeader->Misc.VirtualSize);
		printf("\t0x%p\t%X\t\tVirtual Address\n", (BYTE*)&sectionHeader->VirtualAddress - fileData, sectionHeader->VirtualAddress);
		printf("\t0x%p\t%X\t\tSize Of Raw Data\n", (BYTE*)&sectionHeader->SizeOfRawData - fileData, sectionHeader->SizeOfRawData);
		printf("\t0x%p\t%X\t\tPointer To Raw Data\n", (BYTE*)&sectionHeader->PointerToRawData - fileData, sectionHeader->PointerToRawData);
		//printf("\t\t0x%x\t\tPointer To Relocations\n", sectionHeader->PointerToRelocations); 		
		//printf("\t\t0x%x\t\tPointer To Line Numbers\n", sectionHeader->PointerToLinenumbers); 		
		//printf("\t\t0x%x\t\tNumber Of Relocations\n", sectionHeader->NumberOfRelocations); 		
		//printf("\t\t0x%x\t\tNumber Of Line Numbers\n", sectionHeader->NumberOfLinenumbers); 		
		printf("\t0x%p\t%X\tCharacteristics\n", (BYTE*)&sectionHeader->Characteristics - fileData, sectionHeader->Characteristics);
		if (importDirectoryRVA >= sectionHeader->VirtualAddress && importDirectoryRVA < sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize)
			importSection = sectionHeader;
		if (exportDirectoryRVA >= sectionHeader->VirtualAddress && exportDirectoryRVA < sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize)
			exportSection = sectionHeader;
		sectionHeader++;
	}


	printf("\n************** DLL EXPORTS **************\n");
	if (imageNTHeaders->OptionalHeader.DataDirectory[0].Size == 0)
		printf("No Exports!");
	else
	{
		DWORD rawOffsetExport = (DWORD)fileData + exportSection->PointerToRawData;
		PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)(rawOffsetExport + (exportDirectoryRVA - exportSection->VirtualAddress));

		printf("0x%p\t%s\n", exportSection->PointerToRawData+exportDirectory->Name-exportSection->VirtualAddress, rawOffsetExport + exportDirectory->Name - exportSection->VirtualAddress);
		printf("0x%p\tNumber of functions: %d\n",  (BYTE*)&exportDirectory->NumberOfFunctions-fileData, exportDirectory->NumberOfFunctions);
		printf("0x%p\tNumber of names    : %d\n", (BYTE*)&exportDirectory->NumberOfNames - fileData, exportDirectory->NumberOfNames);
		printf("\tOrdinal\t  Address\t\tName\n");
		DWORD* NameAddr = (DWORD * )(rawOffsetExport + exportDirectory->AddressOfNames - exportSection->VirtualAddress);
		WORD* Ordinal = (WORD*)(rawOffsetExport + exportDirectory->AddressOfNameOrdinals - exportSection->VirtualAddress);
		DWORD* FuncAddr = (DWORD*)(rawOffsetExport + exportDirectory->AddressOfFunctions - exportSection->VirtualAddress);
		for (int i = 0; i < exportDirectory->NumberOfNames; i++)
		{
			printf("\t%d\t", Ordinal[i]+1);
			printf("0x%p\t", FuncAddr[Ordinal[i]]);
			printf("%s", rawOffsetExport + NameAddr[i] - exportSection->VirtualAddress);
			printf("\n");
		}
	}

	DWORD rawOffsetImport = (DWORD)fileData + importSection->PointerToRawData;
	importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(rawOffsetImport + (importDirectoryRVA - importSection->VirtualAddress));
	printf("\n\n************** DLL IMPORTS **************\n");

	DWORD thunk = NULL;
	int countDLL;
	for (countDLL=0; importDescriptor->Name != 0; importDescriptor++)
	{
		// imported dll modules 		
		printf("0x%p\t%s\n\n", importSection->PointerToRawData + (importDescriptor->Name - importSection->VirtualAddress), rawOffsetImport + (importDescriptor->Name - importSection->VirtualAddress));
		thunk = importDescriptor->OriginalFirstThunk == 0 ? importDescriptor->FirstThunk : importDescriptor->OriginalFirstThunk;
		thunkData = (PIMAGE_THUNK_DATA)(rawOffsetImport + (thunk - importSection->VirtualAddress));
		// dll exported functions 
		int countFunc;

		printf("\tHint\t FunctionName\n");
		for (countFunc = 0; thunkData->u1.AddressOfData != 0; thunkData++)
		{
			if (thunkData->u1.AddressOfData > 0x80000000)
				//show lower bits of the value to get the ordinal
				printf("\tOrdinal: %x\n", (WORD)thunkData->u1.AddressOfData);
			else
				printf("\t%04X\t%s\n", *(WORD*)(rawOffsetImport + (thunkData->u1.AddressOfData - importSection->VirtualAddress)), (rawOffsetImport + (thunkData->u1.AddressOfData - importSection->VirtualAddress + 2)));
			countFunc++;
		}
		countDLL++;
		printf("\t\t\t%d functions\n\n", countFunc);
	}
	printf("Number of Dlls : %d\n\n", countDLL);

	printf("\n************** Parser Down **************\n");
}
