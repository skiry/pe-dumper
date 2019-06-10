#include <Windows.h>
#include <stdio.h>
#include <tchar.h>
#include <strsafe.h>

void PrintFileHeader(PIMAGE_FILE_HEADER FileHeader);
void PrintOptionalHeader(PIMAGE_NT_HEADERS*);
void PrintSections(PIMAGE_NT_HEADERS* NtHeader);
void PrintExports(PIMAGE_NT_HEADERS* NtHeader);
void PrintImports(PIMAGE_NT_HEADERS* NtHeader);
DWORD RvaToFa(PIMAGE_NT_HEADERS*, DWORD);

BYTE* fileView;
int _tmain(int argc, TCHAR *argv[])
{
    if (argc != 2)
    {
        printf("[Usage]: <fileName to dump>\n");
        return -1;
    }

    HANDLE sourceFile = INVALID_HANDLE_VALUE;
    HANDLE fileMapping = NULL;
    fileView = NULL;
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeader;

    sourceFile = CreateFile(
        argv[1],
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (GetLastError() == ERROR_FILE_NOT_FOUND)
    {
        printf("[Error] File does not exist.\n");
        goto cleanup;
    }

    if (INVALID_HANDLE_VALUE == sourceFile)
    {
        printf("[Error] Unexpected error trying to open the file.\n");
        goto cleanup;
    }

    fileMapping = CreateFileMapping(
        sourceFile,
        NULL,
        PAGE_READONLY,
        0,
        0,
        NULL
    );

    if (NULL == fileMapping)
    {
        printf("[Error] Unexpected error trying to map the file.\n");
        goto cleanup;
    }

    fileView = (BYTE*)MapViewOfFile(
        fileMapping,
        FILE_MAP_READ,
        0,
        0,
        0
    );

    if (NULL == fileView)
    {
        printf("[Error] Unexpected error trying to map a view of the file mapping.\n");
        goto cleanup;
    }

    pDosHeader = (IMAGE_DOS_HEADER*)fileView;
    if ('ZM' != pDosHeader->e_magic)
    {
        printf("[Error] File is not MZ.\n");
        goto cleanup;
    }

    pNtHeader = (IMAGE_NT_HEADERS*)((BYTE*)fileView + pDosHeader->e_lfanew);
    if ('EP' != pNtHeader->Signature)
    {
        printf("[Error] File is not PE.\n");
        goto cleanup;
    }

    PrintFileHeader(&(pNtHeader->FileHeader));
    PrintOptionalHeader(&pNtHeader);
    PrintSections(&pNtHeader);
    PrintExports(&pNtHeader);
    PrintImports(&pNtHeader);

cleanup:
    if (NULL != fileView)
    {
        UnmapViewOfFile(fileView);
        fileView = NULL;
    }

    if (NULL != fileMapping)
    {
        CloseHandle(fileMapping);
        fileMapping = NULL;
    }

    if (INVALID_HANDLE_VALUE != sourceFile)
    {
        CloseHandle(sourceFile);
        sourceFile = INVALID_HANDLE_VALUE;
    }
    return 0;
}

DWORD RvaToFa(PIMAGE_NT_HEADERS* NtHeader, DWORD Rva)
{
    PIMAGE_NT_HEADERS pNtHeader = *NtHeader;
    IMAGE_SECTION_HEADER* pSectionHeader = (PIMAGE_SECTION_HEADER)(
        (BYTE*)pNtHeader +
        sizeof(DWORD) +
        sizeof(IMAGE_FILE_HEADER) +
        pNtHeader->FileHeader.SizeOfOptionalHeader);

    for (WORD index = 0; index < pNtHeader->FileHeader.NumberOfSections; index++)
    {
        if (Rva >= pSectionHeader[index].VirtualAddress
            && Rva < (pSectionHeader[index].Misc.VirtualSize + pSectionHeader[index].VirtualAddress))
        {
            return (DWORD)(fileView + Rva - pSectionHeader[index].VirtualAddress) + pSectionHeader[index].PointerToRawData;
        }
    }

    return 0;
}

void PrintFileHeader(PIMAGE_FILE_HEADER FileHeader)
{
    printf("File Header:\n");
    printf("-Machine:%X\n", FileHeader->Machine);
    printf("-NumberOfSections:%X\n", FileHeader->NumberOfSections);
    printf("-Characteristics:%X\n", FileHeader->Characteristics);
}

void PrintOptionalHeader(PIMAGE_NT_HEADERS* NtHeader)
{
    PIMAGE_OPTIONAL_HEADER optionalHeader = (PIMAGE_OPTIONAL_HEADER)(&(*NtHeader)->OptionalHeader);
    printf("Optional Header:\n");
    if (RvaToFa(NtHeader, optionalHeader->AddressOfEntryPoint) == 0)
    {
        printf("undef\n");
    }
    else
    {
        printf("-AddressOfEntryPoint:%X\n", RvaToFa(NtHeader, optionalHeader->AddressOfEntryPoint));
    }
    printf("-ImageBase:%X\n", optionalHeader->ImageBase);
    printf("-SectionAlignment:%X\n", optionalHeader->SectionAlignment);
    printf("-FileAlignment:%X\n", optionalHeader->FileAlignment);
    printf("-Subsystem:%X\n", optionalHeader->Subsystem);
    printf("-NumberOfRvaAndSizes:%X\n", optionalHeader->NumberOfRvaAndSizes);
}

void PrintSections(PIMAGE_NT_HEADERS* NtHeader)
{
    PIMAGE_SECTION_HEADER pSectionHeader;
    PIMAGE_NT_HEADERS pNtHeader = *NtHeader;

    pSectionHeader = (PIMAGE_SECTION_HEADER)(
        (BYTE*)pNtHeader +
        sizeof(DWORD) +
        sizeof(IMAGE_FILE_HEADER) +
        pNtHeader->FileHeader.SizeOfOptionalHeader);

    printf("Sections:\n");
    for (WORD sectionIndex = 0; sectionIndex < pNtHeader->FileHeader.NumberOfSections; ++sectionIndex)
    {
        _tprintf_s(TEXT("%.8s,%X,%X\n"),
            pSectionHeader[sectionIndex].Name,
            pSectionHeader[sectionIndex].PointerToRawData,
            pSectionHeader[sectionIndex].SizeOfRawData);
    }
}


void PrintExports(PIMAGE_NT_HEADERS* NtHeader)
{
    PIMAGE_NT_HEADERS pNtHeader = *NtHeader;
    IMAGE_OPTIONAL_HEADER optionalHeader = pNtHeader->OptionalHeader;

    printf("Exports:\n");

    if (IMAGE_DIRECTORY_ENTRY_EXPORT >= optionalHeader.NumberOfRvaAndSizes ||
        optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0)
    {
        return;
    }

    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)RvaToFa(
        NtHeader,
        optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    );

    if (exportDirectory == 0)
    {
        printf("undef\n");
        return;
    }

    PDWORD functions = (PDWORD)RvaToFa(
        NtHeader,
        exportDirectory->AddressOfFunctions
    );

    if (functions == 0)
    {
        printf("undef\n");
        return;
    }

    PDWORD names = (PDWORD)RvaToFa(
        NtHeader,
        exportDirectory->AddressOfNames
    );

    if (names == 0)
    {
        printf("undef\n");
        return;
    }

    PWORD nameOrdinals = (PWORD)RvaToFa(
        NtHeader,
        exportDirectory->AddressOfNameOrdinals
    );

    if (nameOrdinals == 0)
    {
        printf("undef\n");
        return;
    }

    for (DWORD functionIndex = 0; functionIndex < exportDirectory->NumberOfFunctions; ++functionIndex)
    {
        if (functions[functionIndex] != 0)
        {
            for (DWORD nameOrdinalIndex = 0; nameOrdinalIndex < exportDirectory->NumberOfNames; ++nameOrdinalIndex)
            {
                if (nameOrdinals[nameOrdinalIndex] == functionIndex)
                {
                    DWORD name = RvaToFa(NtHeader, names[nameOrdinalIndex]);
                    if (name == 0)
                    {
                        printf("undef\n");
                    }
                    else
                    {
                        _tprintf_s(TEXT("%s"), (TCHAR*)name);
                        break;
                    }
                }
            }
            DWORD fa = RvaToFa(NtHeader, functions[functionIndex]);
            if (fa == 0)
            {
                printf("undef");
            }
            else
            {
                printf(",%X,%X\n", functionIndex + exportDirectory->Base, fa);
            }
        }
    }
}

void PrintImports(PIMAGE_NT_HEADERS* NtHeader)
{
    PIMAGE_NT_HEADERS pNtHeader = *NtHeader;
    IMAGE_OPTIONAL_HEADER optionalHeader = pNtHeader->OptionalHeader;
    
    printf("Imports:\n");

    if (IMAGE_DIRECTORY_ENTRY_IMPORT >= optionalHeader.NumberOfRvaAndSizes ||
        optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0)
    {
        return;
    }

    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)RvaToFa(
        NtHeader,
        optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
    );

    if (importDescriptor == 0)
    {
        printf("undef\n");
        return;
    }

    while (importDescriptor->Name)
    {
        DWORD name = RvaToFa(NtHeader, importDescriptor->Name);
        if (name == 0)
        {
            printf("undef\n");
            continue;
        }
        else
        {
            PIMAGE_THUNK_DATA thunkData = (PIMAGE_THUNK_DATA)RvaToFa(
                NtHeader,
                importDescriptor->OriginalFirstThunk
            );

            if (thunkData == 0)
            {
                printf("undef\n");
                continue;
            }

            while (thunkData->u1.AddressOfData)
            {
                _tprintf_s(TEXT("%s,"), (TCHAR*)name);
                if (IMAGE_SNAP_BY_ORDINAL(thunkData->u1.Ordinal))
                {
                    printf("%X\n", IMAGE_ORDINAL(thunkData->u1.Ordinal));
                }
                else
                {
                    PIMAGE_IMPORT_BY_NAME nameImport = (PIMAGE_IMPORT_BY_NAME)RvaToFa(
                        NtHeader,
                        thunkData->u1.AddressOfData);

                    if (nameImport == 0)
                    {
                        printf("undef\n");
                        continue;
                    }

                    printf("%s\n", nameImport->Name);
                }
                ++thunkData;
            }

        }
        ++importDescriptor;
    }
}