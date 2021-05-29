// dllmain.cpp : Defines the entry point for the DLL application.

//  
//    Test solution that demonstrates DLL injection into all running processes
//    Copyright (c) 2021 www.dennisbabkin.com
//
//        https://dennisbabkin.com/blog/?i=AAA10800
//
//    Credit: Rbmm
//
//        https://github.com/rbmm/INJECT
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//    
//        https://www.apache.org/licenses/LICENSE-2.0
//    
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.
//  
//


#include "pch.h"

#include "DllTypes.h"           //Custom types



//HOW TO SET UP PROJECT TO BUILD WITHOUT CRT:
//
//  1. Configuration Properties -> Linker -> All options -> Ignore All Default Libraries => Yes (/NODEFAULTLIB)
//
//  2. Configuration Properties -> Linker -> All options -> Entry Point => DllMain
//
//  3. Configuration Properties -> Linker -> Input -> Module Definition File => Exports.def
//
//  4. Configuration Properties -> Linker -> Input -> Additional Dependencies => add ntdllp.lib; to the existing items (in front)
//
//  5. Configuration Properties -> C/C++ -> Code Generation -> Security Checks =? Disable Security Check (/GS-)
//
//  6. Configuration Properties -> C/C++ -> Code Generation -> Control Flow Guard => Yes (/guard:cf)
//
//  7. Configuration Properties -> C/C++ -> General -> SDL checks => No (/sdl-)
//
//  8. Add loadcfg.c file (keep the name) into Source Files, and then:
//      - go into its Properties in Solution Explorer:
//             - Configuration Properties -> C/C++ -> Precompiled Headers => Not Using Precompiled Headers
//             - [For Debug configuration]: Configuration Properties -> General -> Excluded from build => Yes




PTEB Get_TEB();
PPEB Get_PEB(PTEB pTeb);
NTSTATUS LogToFileFmt(const char* pstrFmt, ...);


extern "C" void __stdcall UserModeNormalRoutine(PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2);




BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        //__debugbreak();             //User-mode breakpoint

        PTEB pTEB = Get_TEB();
        PPEB pPEB = Get_PEB(pTEB);

        //Get current PID
        CLIENT_ID* pCID = (CLIENT_ID*)((BYTE*)pTEB + sizeof(NT_TIB) + sizeof(void*));
        ULONG uiPID = (ULONG)(ULONG_PTR)pCID->UniqueProcess;

        //Get current time
        LARGE_INTEGER liSt = {};
        NtQuerySystemTime(&liSt);
        RtlSystemTimeToLocalTime(&liSt, &liSt);
        TIME_FIELDS tfSt = {};
        RtlTimeToTimeFields(&liSt, &tfSt);

        //We can't use SEH!
        if(pPEB->ProcessParameters)
        {
            //Simply output where we ran from
            DbgPrintLine("%04u-%02u-%02u %02u:%02u:%02u.%03u > PID=%u: \"%wZ\""
                ,
                tfSt.Year, tfSt.Month, tfSt.Day, tfSt.Hour, tfSt.Minute, tfSt.Second, tfSt.Milliseconds,
                uiPID, &pPEB->ProcessParameters->ImagePathName
            );
        }
        else
        {
            //No path
             DbgPrintLine("%04u-%02u-%02u %02u:%02u:%02u.%03u > PID=%u: no path"
                ,
                tfSt.Year, tfSt.Month, tfSt.Day, tfSt.Hour, tfSt.Minute, tfSt.Second, tfSt.Milliseconds,
                uiPID
            );
       }

    }
    break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}



PTEB Get_TEB()
{
    //RETURN:
    //      = Pointer to TEB for the current thread
#ifdef _WIN64
    return (PTEB)__readgsqword((ULONG)offsetof(NT_TIB, Self));
#elif _WIN32
    return (PTEB)__readfsdword((ULONG)offsetof(NT_TIB, Self));
#else
#error unsupported_CPU
#endif
}

PPEB Get_PEB(PTEB pTeb)
{
    //RETURN:
    //      = Pointer to PEB for the current thread
    return pTeb->ProcessEnvironmentBlock;
}



void __declspec(dllexport) __cdecl f1(const void* pPtr)
{
    //Dummy export function - it should never be called

    //Define this module's name
    //INFO: It will be searchable from the PE file after this DLL in injected
    static SEARCH_TAG_W srchTag = { GUID_SearchTag_DllName_Bin, L"" INJECTED_DLL_FILE_NAME };

    //This part is needed to keep the statis variable in the executable
    if(!memcmp(&srchTag, pPtr, sizeof(srchTag)))
    {
        __debugbreak();             //User-mode breakpoint

        //The following is needed to mark UserModeNormalRoutine function as a valid call-target when CFG is enabled
        //with the "Export suppression" option on. Otherwise invoking it for our APC will crash the target process!
        ZwQueueApcThread(0, UserModeNormalRoutine, 0, 0, 0);
    }
}




NTSTATUS LogToFile(const char* pstrOutput, LPCTSTR pStrFile)
{
    //Write 'pstrOutput' string at the end of the 'pStrFile' file
    //RETURN:
    //      = Status of the operation
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if(pstrOutput &&
        pstrOutput[0])
    {
        //Get length of output
        UINT cbSize = 0;
        while(pstrOutput[cbSize])
            cbSize++;

        //Convert to NT file path
        UNICODE_STRING uStrFile;
        status = RtlDosPathNameToNtPathName_U_WithStatus(pStrFile, &uStrFile, NULL, NULL);
        if(NT_SUCCESS(status))
        {
            OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, const_cast<PUNICODE_STRING>(&uStrFile), OBJ_CASE_INSENSITIVE };

            IO_STATUS_BLOCK iosb;

            //INFO: The use of the FILE_APPEND_DATA flag will make writing into our file atomic!
            HANDLE hFile;
            status = NtCreateFile(&hFile, FILE_APPEND_DATA | SYNCHRONIZE, &oa, &iosb, 0,
                FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, NULL);
            if(NT_SUCCESS(status))
            {
                status = NtWriteFile(hFile, NULL, NULL, NULL, &iosb, (PVOID)pstrOutput, cbSize, NULL, NULL);

                //Close file
                NtClose(hFile);
            }

            //Free string
            RtlFreeUnicodeString(&uStrFile);
        }
    }

    return status;
}



NTSTATUS LogToFileFmt(const char* pstrFmt, ...)
{
    //Output formatted string from 'pstrFmt' into the log file
    //IMPORTANT: The string cannot be longer than 512 characters!
    va_list argList;
    va_start(argList, pstrFmt);

    char buff[512];
    buff[0] = 0;
    vsprintf_s(buff, sizeof(buff), pstrFmt, argList);
    buff[sizeof(buff) - 1] = 0;     //Safety null

    NTSTATUS status = LogToFile(buff, DBG_FILE_PATH);

    va_end(argList);

    return status;
}




