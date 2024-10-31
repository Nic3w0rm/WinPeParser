#include "Include\Logger.h"
#include "Include\PEParser.h"
#include "Include\Util.h"

#include <iostream>
#include <string>
#include <sstream>
#include <conio.h>

int main(int argc, char* argv[])
{
    if (argc != 2)
    {
        std::cout << "Example of how to use the program in Terminal(cmd): WinPeParser.exe <PID || file path>" << std::endl;
        return 1;
    }

    std::string input = argv[1];
    std::string filePath;
    DWORD pid = 0;

    if (IsNumber(input))
    {
        std::istringstream iss(input);
        iss >> pid;
        if (!GetExecPathFromPID(pid, filePath))
        {
            DbgError("01__Failed to retrieve executable path for PID " + std::to_string(pid) + ".", 0);
            return 1;
        }
        std::cout << "analyzing executable of PID " << pid << ": " << filePath << std::endl;
    }
    else
    {
        filePath = input;
        DbgLog("File path provided: " + filePath);
    }
    PEParser parser(filePath);
    
    if (!parser.ParsePEFile())
    {
        DbgError("02__Failed to parse PE file: " + filePath, 0);
        return 1;
    }

    parser.PrintImports();
    parser.PrintExports();

    return 0;
}
