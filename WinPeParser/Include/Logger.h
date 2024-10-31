#ifndef LOGGER_H
#define LOGGER_H

#include <string>
#include <windows.h>

class Logger
{
public:
    static void LogDebug(const std::string& message);
    static void LogError(const std::string& message, NTSTATUS ntStatus = 0);
    static std::string NTStatusToString(NTSTATUS status);
};

#ifdef _DEBUG
#define DbgLog(message) Logger::LogDebug(message)
#else
#define DbgLog(message)
#endif

#define DbgError(message, status_code) Logger::LogError(message, status_code)
#define ntstatus(status_code) Logger::NTStatusToString(status_code)

#endif // LOGGER_H
