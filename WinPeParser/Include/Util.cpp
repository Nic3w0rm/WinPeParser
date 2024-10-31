#include "Util.h"

bool GetExecPathFromPID(DWORD pid, std::string& exePath)
{
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProc == NULL)
    {
        DbgError("can;t open process with PID " + std::to_string(pid) + ".", 0);
        return false;
    }

    char buffer[MAX_PATH];
    DWORD size = GetModuleFileNameExA(hProc, NULL, buffer, MAX_PATH);
    if (size == 0 || size == MAX_PATH)
    {
        DbgError("Failed to get executable path for PID " + std::to_string(pid) + ".", 0);
        CloseHandle(hProc);
        return false;
    }

    exePath = std::string(buffer);
    CloseHandle(hProc);
    //DbgLog("Exec path: " + exePath);
    return true;
}

bool IsNumber(const std::string& s)
{
    bool result = !s.empty() && std::all_of(s.begin(), s.end(), ::isdigit);
    DbgLog("input arg is number('" + s + "') = " + (result ? "true" : "false"));
    return result;
}



//bool isUserAnAdmin() {
//    BOOL isAdmin = FALSE;
//    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
//    PSID AdministratorsGroup;
//    if (!AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
//        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup)) {
//        return false;
//    }
//    if (!CheckTokenMembership(NULL, AdministratorsGroup, &isAdmin)) {
//        isAdmin = FALSE;
//    }
//    FreeSid(AdministratorsGroup);
//    return isAdmin;
//}
//
//bool relaunchAsAdmin() {
//    if (!isUserAnAdmin()) {
//        char szPath[MAX_PATH];
//        if (GetModuleFileNameA(NULL, szPath, ARRAYSIZE(szPath)) == 0) {
//            DbgError("\n\t-Faild to relaunch as admin...\\ \t - dbg_msg: unable to get module file name.\n\n", 0);
//            return false;
//        }
//
//        SHELLEXECUTEINFOA sei = { sizeof(sei) };
//        sei.lpVerb = "runas";
//        sei.lpFile = szPath;
//        sei.hwnd = NULL;
//        sei.nShow = SW_NORMAL;
//
//        if (!ShellExecuteExA(&sei)) {
//            DWORD dwError = GetLastError();
//            if (dwError == ERROR_CANCELLED) {
//                DbgError("\n\n\t-Error dbg_55\n\n", 0);
//
//            }
//            else {
//                DbgError("\n\n\t-Error dbg_56\n\n", 0);
//            }
//            return false;
//        }
//        exit(0);
//    }
//    return true;
//}