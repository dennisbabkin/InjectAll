//Class that deals with mapping of section (or DLL)

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

#include "DrvTypes.h"			//Custom types




struct DLL_STATS{
	//INFO: Cannot use constructor/destructor!

	SECTION_TYPE secType;				//Tye of section
	PVOID Section;						//If not NULL, Section object (for that DLL being injected)
	ULONG uRVA_ShellCode;				//If not 0, RVA offset to the ShellCode in the injected DLL - must be UserModeNormalRoutine() function in dll_asm64.asm/dll_asm32.asm files
	ULONG uRVA_DllName;					//If not 0, RVA offset of the injected DLL name as null-terminated WCHAR string
	PVOID PreferredAddress;				//If not NULL, preferred load base-address for the injected DLL (after ASLR relocation)
	ULONG SizeOfImage;					//If not 0, size of the section in BYTEs

	bool IsValid()
	{
		//RETURN:
		//		= true if data in this struct is valid
		return Section != NULL &&
			uRVA_ShellCode != 0 &&
			uRVA_DllName != 0 &&
			PreferredAddress != 0 &&
			SizeOfImage != 0;
	}
};


#define ALLOC_TYPE_OnLoadImage PagedPool		//We can do it because: The OS calls the driver's image-load notify routine at PASSIVE_LEVEL





class CSection
{
	//INFO: Cannot use constructor/destructor!

	SECTION_TYPE sectionType;
	RTL_RUN_ONCE SectionSingletonState;

public:
	NTSTATUS Initialize(SECTION_TYPE type);
	NTSTATUS GetSection(DLL_STATS** ppOutSectionInfo = NULL);
	NTSTATUS InjectDLL(DLL_STATS* pDllStats);
	static NTSTATUS MapSectionForShellCode(DLL_STATS* pDllStats, PVOID* pOutBaseAddr = NULL);
	NTSTATUS FreeSection();
private:
	NTSTATUS CreateKnownDllSection(DLL_STATS& outStats);
};

