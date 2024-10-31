#include "Logger.h"
#include <iostream>
#include <sstream>
#include <iomanip>

std::string Logger::NTStatusToString(NTSTATUS status)
{
    typedef LONG(NTAPI* RtlNtStatusToDosErrorFunc)(NTSTATUS status);

    HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
    if (hNtDll)
    {
        RtlNtStatusToDosErrorFunc RtlNtStatusToDosError =
            (RtlNtStatusToDosErrorFunc)GetProcAddress(hNtDll, "RtlNtStatusToDosError");
        if (RtlNtStatusToDosError)
        {
            DWORD winError = RtlNtStatusToDosError(status);
            if (winError != ERROR_MR_MID_NOT_FOUND) 
            {
                char* buffer = nullptr;
                FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, winError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&buffer, 0, NULL);
                if (buffer)
                {
                    std::string ErrorMessage(buffer);
                    LocalFree(buffer);
                    return ErrorMessage;
                }
            }
        }
    }

    std::ostringstream oss;
    oss << "0x" << std::hex << std::uppercase << status;
    return oss.str();
}

void Logger::LogDebug(const std::string& message)
{
#ifdef _DEBUG
    std::cout << " [ + ] " << "[DEBUG] -> " << message << std::endl;
#endif
}

void Logger::LogError(const std::string& message, NTSTATUS ntStatus)
{
    std::cerr << " [ - ] " << "[ERROR] -> " << message;

    if (ntStatus != 0)
    {
        std::string ntStatusString = NTStatusToString(ntStatus);
        std::cerr << " (NTSTATUS: " << ntStatusString << ")";
    }
    else
    {
        DWORD errorCode = GetLastError();
        if (errorCode != 0)
        {
            LPSTR ErrorMessage = nullptr;
            FormatMessageA( FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, errorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&ErrorMessage, 0, NULL);
            if (ErrorMessage)
            {
                std::cerr << " --Error Code " << errorCode << ": " << ErrorMessage;
                LocalFree(ErrorMessage);
            }
            else
            {
                std::cerr << " --Error Code " << errorCode;
            }
        }
    }
    std::cerr << std::endl;
}
