#include "PEParser.h"

PEParser::PEParser(const std::string& file)
    : filename(file), handleFile(NULL), handleFileMapping(NULL), FileBase(NULL),
    NtHeaders(NULL), is64Bit(false), SectionHeaders(NULL), numberOfSections(0)
{
}

PEParser::~PEParser()
{
    UnloadFile();
}

bool PEParser::LoadFile()
{
    handleFile = CreateFileA(filename.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (handleFile == INVALID_HANDLE_VALUE)
    {
        DbgError(std::string("31__opening file: ") + filename, 0);
        return false;
    }

    handleFileMapping = CreateFileMappingA(handleFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (handleFileMapping == NULL)
    {
        DbgError("32__creating file mapping.", 0);
        CloseHandle(handleFile);
        return false;
    }

    FileBase = MapViewOfFile(handleFileMapping, FILE_MAP_READ, 0, 0, 0);
    if (FileBase == NULL)
    {
        DbgError("33__mapping view of file.", 0);
        CloseHandle(handleFileMapping);
        CloseHandle(handleFile);
        return false;
    }

    DbgLog("Mapped successfully.");
    return true;
}

void PEParser::UnloadFile()
{
    if (FileBase)
    {
        UnmapViewOfFile(FileBase);
        FileBase = NULL;
    }

    if (handleFileMapping)
    {
        CloseHandle(handleFileMapping);
        handleFileMapping = NULL;
    }

    if (handleFile)
    {
        CloseHandle(handleFile);
        handleFile = NULL;
    }
}

DWORD PEParser::RVAToOffset(DWORD rva)
{
    for (DWORD i = 0; i < numberOfSections; i++)
    {
        DWORD sectionStart = SectionHeaders[i].VirtualAddress;
        DWORD sectionSize = SectionHeaders[i].SizeOfRawData;

        if (rva >= sectionStart && rva < (sectionStart + sectionSize))
        {
            DWORD delta = rva - SectionHeaders[i].VirtualAddress;
            DWORD offset = SectionHeaders[i].PointerToRawData + delta;
            DbgLog(std::string("+++RVA 0x") + std::to_string(rva) + " converted to offset 0x" + std::to_string(offset));
            return offset;
        }
    }
    DbgError(std::string("34__can't convert RVA to offset: 0x") + std::to_string(rva), 0);
    return 0;
}

bool PEParser::ParsePEFile()
{
    if (!LoadFile())
        return false;

    PIMAGE_DOS_HEADER pDOSHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(FileBase);
    if (pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        DbgError("35__invalid PE file.", 0);
        return false;
    }

    NtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<BYTE*>(FileBase) + pDOSHeader->e_lfanew
        );
    if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        DbgError("36__invalid PE signature.", 0);
        return false;
    }

    numberOfSections = NtHeaders->FileHeader.NumberOfSections;
    SectionHeaders = reinterpret_cast<PIMAGE_SECTION_HEADER>(
        reinterpret_cast<BYTE*>(&NtHeaders->OptionalHeader) + NtHeaders->FileHeader.SizeOfOptionalHeader
        );

    WORD magic = NtHeaders->OptionalHeader.Magic;
    is64Bit = (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

    DbgLog(std::string("+++Parsed successfully. Architecture: ") + (is64Bit ? "64-bit" : "32-bit"));
    return true;
}

void PEParser::ParseImportTable()
{
    IMAGE_DATA_DIRECTORY importData;

    if (is64Bit)
    {
        PIMAGE_OPTIONAL_HEADER64 pOpt = reinterpret_cast<PIMAGE_OPTIONAL_HEADER64>(&NtHeaders->OptionalHeader);
        importData = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    }
    else
    {
        PIMAGE_OPTIONAL_HEADER32 pOpt = reinterpret_cast<PIMAGE_OPTIONAL_HEADER32>(&NtHeaders->OptionalHeader);
        importData = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    }

    if (importData.VirtualAddress == 0)
    {
        DbgLog("Imports not found.");
        return;
    }

    DWORD importOffset = RVAToOffset(importData.VirtualAddress);
    if (importOffset == 0)
    {
        DbgError("37__convert import directory RVA to offset.", 0);
        return;
    }

    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
        reinterpret_cast<BYTE*>(FileBase) + importOffset
        );
    std::cout << "Imported functions:" << std::endl;

    while (importDescriptor->Name != 0)
    {
        DWORD nameOffset = RVAToOffset(importDescriptor->Name);
        if (nameOffset == 0)
        {
            DbgError("38__Failed to convert Dll name to offset.", 0);
            break;
        }

        char* dllName = reinterpret_cast<char*>(reinterpret_cast<BYTE*>(FileBase) + nameOffset);
        std::cout << "DLL Name: " << dllName << std::endl;

        DWORD thunkRVA = (importDescriptor->OriginalFirstThunk != 0) ? importDescriptor->OriginalFirstThunk : importDescriptor->FirstThunk;
        DWORD thunkOffset = RVAToOffset(thunkRVA);

        if (thunkOffset == 0)
        {
            DbgError("39__Can't convert thunk RVA to offset.", 0);
            break;
        }

        if (is64Bit)
        {
            PIMAGE_THUNK_DATA64 tData = reinterpret_cast<PIMAGE_THUNK_DATA64>(
                reinterpret_cast<BYTE*>(FileBase) + thunkOffset
                );
            while (tData->u1.AddressOfData != 0)
            {
                if (tData->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
                {
                    WORD ordinal = static_cast<WORD>(tData->u1.Ordinal & 0xFFFF);
                    std::cout << "  Ordinal: " << ordinal << std::endl;
                }
                else
                {
                    DWORD importByNameRVA = static_cast<DWORD>(tData->u1.AddressOfData);
                    DWORD impByNameOffset = RVAToOffset(importByNameRVA);
                    if (impByNameOffset == 0)
                    {
                        DbgError("39.1__Failed to convert import to offset.(64-bit)", 0);
                        break;
                    }
                    PIMAGE_IMPORT_BY_NAME pImportByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
                        reinterpret_cast<BYTE*>(FileBase) + impByNameOffset
                        );
                    std::cout << "  Function: " << pImportByName->Name << std::endl;
                }
                tData++;
            }
        }
        else
        {
            PIMAGE_THUNK_DATA32 tData = reinterpret_cast<PIMAGE_THUNK_DATA32>(
                reinterpret_cast<BYTE*>(FileBase) + thunkOffset
                );
            while (tData->u1.AddressOfData != 0)
            {
                if (tData->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
                {
                    WORD ordinal = static_cast<WORD>(tData->u1.Ordinal & 0xFFFF);
                    std::cout << "  Ordinal: " << ordinal << std::endl;
                }
                else
                {
                    DWORD importByNameRVA = tData->u1.AddressOfData;
                    DWORD impByNameOffset = RVAToOffset(importByNameRVA);
                    if (impByNameOffset == 0)
                    {
                        DbgError("39.2__Failed to convert import to offset.(32-bit)", 0);
                        break;
                    }
                    PIMAGE_IMPORT_BY_NAME pImportByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
                        reinterpret_cast<BYTE*>(FileBase) + impByNameOffset
                        );
                    std::cout << "  Function: " << pImportByName->Name << std::endl;
                }
                tData++;
            }
        }

        importDescriptor++;
    }
}

void PEParser::ParseExportTable()
{
    IMAGE_DATA_DIRECTORY exportDirData;
    if (is64Bit)
    {
        PIMAGE_OPTIONAL_HEADER64 pOpt = reinterpret_cast<PIMAGE_OPTIONAL_HEADER64>(&NtHeaders->OptionalHeader);
        exportDirData = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    }
    else
    {
        PIMAGE_OPTIONAL_HEADER32 pOpt = reinterpret_cast<PIMAGE_OPTIONAL_HEADER32>(&NtHeaders->OptionalHeader);
        exportDirData = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    }

    if (exportDirData.VirtualAddress == 0)
    {
        DbgLog("Exports not found.");
        return;
    }

    DWORD exportDirOffset = RVAToOffset(exportDirData.VirtualAddress);
    if (exportDirOffset == 0)
    {
        DbgError("Failed to convert EAT dir RVA to offset.", 0);
        return;
    }

    PIMAGE_EXPORT_DIRECTORY pExportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
        reinterpret_cast<BYTE*>(FileBase) + exportDirOffset
        );
    DWORD* functions = reinterpret_cast<DWORD*>(reinterpret_cast<BYTE*>(FileBase) + RVAToOffset(pExportDirectory->AddressOfFunctions));
    DWORD* names = reinterpret_cast<DWORD*>(reinterpret_cast<BYTE*>(FileBase) + RVAToOffset(pExportDirectory->AddressOfNames));
    WORD* ordinals = reinterpret_cast<WORD*>(reinterpret_cast<BYTE*>(FileBase) + RVAToOffset(pExportDirectory->AddressOfNameOrdinals));

    std::cout << "EAT functions:" << std::endl;
    for (DWORD i = 0; i < pExportDirectory->NumberOfNames; i++)
    {
        DWORD nameRVA = names[i];
        DWORD nameOffset = RVAToOffset(nameRVA);
        if (nameOffset == 0)
        {
            DbgError("Failed to convert EAT function name RVA to offset.", 0);
            continue;
        }
        char* functionName = reinterpret_cast<char*>(reinterpret_cast<BYTE*>(FileBase) + nameOffset);
        std::cout << "  Function: " << functionName << std::endl;
    }
}

void PEParser::PrintImports()
{
    ParseImportTable();
}

void PEParser::PrintExports()
{
    ParseExportTable();
}
