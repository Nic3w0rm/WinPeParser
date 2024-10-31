#ifndef PEPARSER_H
#define PEPARSER_H

#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include "Logger.h"

class PEParser
{
public:
    PEParser(const std::string& filename);
    ~PEParser();

    bool ParsePEFile();
    void PrintImports();
    void PrintExports();

private:
    std::string filename;
    HANDLE handleFile;
    HANDLE handleFileMapping;
    LPVOID FileBase;
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_SECTION_HEADER SectionHeaders;
    bool is64Bit;
    WORD numberOfSections;

    DWORD RVAToOffset(DWORD rva);
    bool LoadFile();
    void UnloadFile();
    void ParseImportTable();
    void ParseExportTable();
};

#endif // PEPARSER_H
