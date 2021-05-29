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


#include "CFunc.h"




BOOLEAN CFunc::IsSuffixedUnicodeString(PCUNICODE_STRING FullName, PCUNICODE_STRING ShortName, BOOLEAN CaseInsensitive)
{
	//Check if 'FullName' ends with 'ShortName'
	//'CaseInsensitive' = TRUE to check in case-insensitive way (or ignore letter case)
	//RETURN:
	//		= TRUE if yes

	if(FullName &&
		ShortName &&
		ShortName->Length <= FullName->Length)
	{
		UNICODE_STRING ustr = {
			ShortName->Length,
			ustr.Length,
			(PWSTR)RtlOffsetToPointer(FullName->Buffer, FullName->Length - ustr.Length)
		};

		return RtlEqualUnicodeString(&ustr, ShortName, CaseInsensitive);
	}

	return FALSE;
}





BOOLEAN CFunc::IsMappedByLdrLoadDll(PCUNICODE_STRING ShortName)
{
	//Check if this thread runs from within LdrLoadDll() function for the 'ShortName' module.
	//INFO: Otherwise the call could have come from someone invoking ZwMapViewOfSection with SEC_IMAGE
	//      Ex: smss.exe can map kernel32.dll during creation of \\KnownDlls (in that case ArbitraryUserPointer will be 0)
	//      ex: WOW64 processes map kernel32.dll several times (32 and 64-bit version) with WOW64_IMAGE_SECTION or NOT_AN_IMAGE
	//RETURN:
	//		- TRUE if yes
	UNICODE_STRING Name;

	__try
	{
		PNT_TIB Teb = (PNT_TIB)PsGetCurrentThreadTeb();
		if(!Teb ||
			!Teb->ArbitraryUserPointer)
		{
			//This is not it
			return FALSE;
		}

		Name.Buffer = (PWSTR)Teb->ArbitraryUserPointer;

		//Check that we have a valid user-mode address
		ProbeForRead(Name.Buffer, sizeof(WCHAR), __alignof(WCHAR));

		//Check buffer length
		Name.Length = (USHORT)wcsnlen(Name.Buffer, MAXSHORT);
		if(Name.Length == MAXSHORT)
		{
			//Name is too long
			return FALSE;
		}

		Name.Length *= sizeof(WCHAR);
		Name.MaximumLength = Name.Length;

		//See if it's our needed module
		return IsSuffixedUnicodeString(&Name, ShortName);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		//Something failed
		DbgPrintLine("#EXCEPTION: (0x%X) IsMappedByLdrLoadDll", GetExceptionCode());
	}

	return FALSE;
}


PCWSTR CFunc::debugGetCurrentProcName(char* pBuff, size_t szcbLn, BOOL bFileNameOnly)
{
	//Retrieves current process name
	//'pBuff' = buffer to use
	//'szcbLn' = size of 'pBuff' in BYTEs. It is recommended to set it to at least to GCPFN_BUFF_SIZE, or larger.
	//'bFileNameOnly' = TRUE to return file name only, FALSE - to get the full path
	//RETURN:
	//		= Pointer to the process image/file path/name, or
	//		= "-", "?" or string with error code otherwise

	//Do we have valid params?
	if(!pBuff ||
		szcbLn < (sizeof(UNICODE_STRING) + 1 * sizeof(WCHAR)) ||
		szcbLn > MAXUSHORT)
	{
		//Bad input
		ASSERT(NULL);
		return L"-";
	}

	UNICODE_STRING* puStr = (UNICODE_STRING*)pBuff;
	PWCH pWBuff = (PWCH)((BYTE*)pBuff + sizeof(UNICODE_STRING));
	puStr->Length = 0;
	puStr->MaximumLength = (USHORT)(szcbLn - sizeof(UNICODE_STRING));
	puStr->Buffer = pWBuff;

	ULONG uicbSzRet = 0;
	NTSTATUS status = ZwQueryInformationProcess(NtCurrentProcess(), ProcessImageFileName, puStr, (ULONG)szcbLn, &uicbSzRet);
	if(status == STATUS_SUCCESS)
	{
		//Safety null
		*(WCHAR*)((BYTE*)pBuff + szcbLn - sizeof(WCHAR)) = 0;

		//Make sure that we have a null-terminated string
		if(puStr->Length + sizeof(WCHAR) <= puStr->MaximumLength)
		{
			*(WCHAR*)((BYTE*)puStr->Buffer + puStr->Length) = 0;
		}

		if(bFileNameOnly)
		{
			//Find last slash
			WCHAR* pLastSlash = NULL;
			for(WCHAR* pS = pWBuff;; pS++)
			{
				WCHAR z = *pS;
				if(!z)
				{
					if(pLastSlash)
					{
						//Use it
						return pLastSlash + 1;
					}

					break;
				}
				else if(z == L'\\')
				{
					pLastSlash = pS;
				}
			}
		}
	}
	else
	{
		//Failed
		if(RtlStringCchPrintfW(pWBuff, (szcbLn - sizeof(UNICODE_STRING)) / sizeof(WCHAR), 
			L"<Err:0x%x>", status) != STATUS_SUCCESS)
		{
			//Failed even here
			ASSERT(NULL);
			return L"?";
		}
	}

	//Return result
	return pWBuff;
}




BOOLEAN CFunc::IsSpecificProcessW(HANDLE ProcessId, const WCHAR* ImageName, BOOLEAN bIsDebugged)
{
	//Checks if process with 'ProcessId' is a specific process by its file name
	//'ImageName' = file name of the process to check (in case-insensitive way)
	//'bIsDebugged' = TRUE to check if kernel debugger is present
	//RETURN:
	//		= TRUE if yes, that is the process
	ASSERT(ImageName);
	BOOLEAN bResult = FALSE;

	PEPROCESS Process;
	if(NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process)))
	{
		//Check for kernel debugger?
		if(!bIsDebugged ||
			PsIsProcessBeingDebugged(Process))
		{
			//Get process handle
			HANDLE hProc;
			if(ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, NULL, 
				PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &hProc) == STATUS_SUCCESS)
			{
				//Get process name
				//INFO: We need for file name, thus can't use PsGetProcessImageFileName which will truncate it past 14 chars
				WCHAR buff[GCPFN_BUFF_SIZE];
				UNICODE_STRING* puStr = (UNICODE_STRING*)buff;
				PWCH pWBuff = (PWCH)((BYTE*)buff + sizeof(UNICODE_STRING));
				puStr->Length = 0;
				puStr->MaximumLength = (USHORT)(sizeof(buff) - sizeof(UNICODE_STRING));
				puStr->Buffer = pWBuff;

				if(ZwQueryInformationProcess(hProc, ProcessImageFileName, puStr, sizeof(buff), NULL) == STATUS_SUCCESS)
				{
					//Safety null
					*(WCHAR*)((BYTE*)buff + sizeof(buff) - sizeof(WCHAR)) = 0;

					//Make sure that we have a null-terminated string
					if(puStr->Length + sizeof(WCHAR) <= puStr->MaximumLength)
					{
						*(WCHAR*)((BYTE*)puStr->Buffer + puStr->Length) = 0;
					}

					//Find file name
					WCHAR* pLastSlash = NULL;
					for(WCHAR* pS = pWBuff;; pS++)
					{
						WCHAR z = *pS;
						if(!z)
						{
							if(pLastSlash)
							{
								//Use it
								pWBuff = pLastSlash + 1;
							}

							break;
						}
						else if(z == L'\\')
						{
							pLastSlash = pS;
						}
					}

					//Compare it to our provided name
					if(_wcsicmp(ImageName, pWBuff) == 0)
					{
						bResult = TRUE;
					}
				}

				//Close the process
				ZwClose(hProc);
			}
		}

		//Dereference process object back
		ObDereferenceObject(Process);
	}

	return bResult;
}




UINT CFunc::FindStringByTag(PVOID BaseAddress, UINT cbSize, const GUID* pTag)
{
	//Locate string that follows 'pTag' in byte array - both must be declared in a static SEARCH_TAG_W struct
	//'BaseAddress' = beginning of the byte array
	//'cbSize' = size of 'BaseAddress' in BYTEs
	//RETURN:
	//		= Offset of the string that follows 'pTag' in BYTEs from the 'BaseAddress'
	//		= -1 if not found
	ASSERT(BaseAddress);

	union
	{
		const BYTE* pS;
		const GUID* pG;
	};

	pS = (const BYTE*)BaseAddress;
	for(const BYTE* pE = pS + cbSize - sizeof(GUID); pS <= pE; pS++)
	{
		if(memcmp(pG, pTag, sizeof(GUID)) == 0)
		{
			//Matched!
			return (UINT)(pS + sizeof(GUID) - (const BYTE*)BaseAddress);
		}
	}

	return (UINT)-1;
}









