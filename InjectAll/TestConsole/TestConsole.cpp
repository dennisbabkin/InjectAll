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



#include <iostream>

#include <Windows.h>

#include "..\Drv\SharedDefs.h"			//Shared definitions

#include <sddl.h>




void SetSD_InjectAllFolder(LPCTSTR pStrFldrPath);



int main()
{
	//SetSD_InjectAllFolder(L"C:\\InjectAll");


	LPCTSTR pStrDllName = L"" INJECTED_DLL_FILE_NAME;
	//LPCTSTR pStrDllName = L"..\\Release\\" INJECTED_DLL_FILE_NAME;

	HMODULE hMod = LoadLibrary(pStrDllName);
	if(hMod)
	{

		::FreeLibrary(hMod);
	}
}




void SetSD_InjectAllFolder(LPCTSTR pStrFldrPath)
{
	PSECURITY_DESCRIPTOR pSD = NULL;
	ULONG uicbSDSize = 0;

	// DACL:
	//		ACCESS_ALLOWED = GENERIC_ALL, SDDL_EVERYONE
	//		ACCESS_ALLOWED = GENERIC_ALL, SDDL_ANONYMOUS
	//		ACCESS_ALLOWED = GENERIC_ALL, ALL_APP_PACKAGES
	//		ACCESS_ALLOWED = GENERIC_ALL, ALL_RESTRICTED_APP_PACKAGES
	// SACL:
	//		MANDATORY_LABEL = Untrusted Mandatory Level
	//
	if(::ConvertStringSecurityDescriptorToSecurityDescriptor(
		L"D:(A;;GA;;;WD)(A;;GA;;;AN)(A;;GA;;;S-1-15-2-1)(A;;GA;;;S-1-15-2-2)S:(ML;;;;;S-1-16-0)",
		SDDL_REVISION_1, &pSD, &uicbSDSize
	))
	{
		HANDLE hFolder = ::CreateFile(pStrFldrPath, WRITE_DAC | WRITE_OWNER,
			FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL, OPEN_EXISTING, 
			FILE_FLAG_BACKUP_SEMANTICS,			//Necessary to open a folder!
			NULL);

		if(hFolder != INVALID_HANDLE_VALUE)
		{
			//Set DACL
			if(::SetKernelObjectSecurity(hFolder, DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION, pSD))
			{
				wprintf(L"SUCCESS: Set SD, file=%s\n", pStrFldrPath);
			}
			else
			{
				wprintf(L"ERROR: (%u) SetKernelObjectSecurity, file=%s\n", ::GetLastError(), pStrFldrPath);
			}

			::CloseHandle(hFolder);
		}
		else
			wprintf(L"ERROR: (%u) CreateFile, file=%s\n", ::GetLastError(), pStrFldrPath);

		::LocalFree(pSD);
	}
	else
		wprintf(L"ERROR: (%u) ConvertStringSecurityDescriptorToSecurityDescriptor, file=%s\n", ::GetLastError(), pStrFldrPath);
}



