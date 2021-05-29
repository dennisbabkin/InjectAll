//Helper functions

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

#pragma once

#include "DrvTypes.h"				//Custom types



#define GCPFN_BUFF_SIZE (sizeof(UNICODE_STRING) + (MAX_PATH + 1) * sizeof(WCHAR))




class CFunc
{
public:
	static BOOLEAN IsSuffixedUnicodeString(PCUNICODE_STRING FullName, PCUNICODE_STRING ShortName, BOOLEAN CaseInsensitive = TRUE);
	static BOOLEAN IsMappedByLdrLoadDll(PCUNICODE_STRING ShortName);
	static PCWSTR debugGetCurrentProcName(char* pBuff, size_t szcbLn, BOOL bFileNameOnly = FALSE);
	static BOOLEAN IsSpecificProcessW(HANDLE ProcessId, const WCHAR* ImageName, BOOLEAN bIsDebugged);
	static UINT FindStringByTag(PVOID BaseAddress, UINT cbSize, const GUID* pTag);
};

