//Main driver entry cpp file

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



#include "CFunc.h"                 //Helper functions
#include "CSection.h"              //Section/DLL specific



//Global variables
extern "C" {
	PDRIVER_OBJECT g_DriverObject;          //Driver object - read-only (for reference counting)
}

IMAGE_LOAD_FLAGS g_Flags;                       //Global notification flags

CSection sec;                                   //Native section object

#ifdef _WIN64
CSection secWow;                                //WOW64 section object (used only for a 64-bit build)
#endif




void OnLoadImage(
  PUNICODE_STRING FullImageName,
  HANDLE ProcessId,
  PIMAGE_INFO ImageInfo
)
{
	//Called back notification that an image is loaded (or mapped in memory)
	//'ProcessId' = process where the image is mapped into (or 0 for a driver)
	UNREFERENCED_PARAMETER(FullImageName);
	UNREFERENCED_PARAMETER(ProcessId);
	UNREFERENCED_PARAMETER(ImageInfo);

	NTSTATUS status;

	ASSERT(FullImageName);
	ASSERT(ImageInfo);

	STATIC_UNICODE_STRING(kernel32, "\\kernel32.dll");


	//We are looking for kernel32.dll only - skip the rest
	if(!ImageInfo->SystemModeImage &&                                                //Skip anything mapped into kernel
		ProcessId == PsGetCurrentProcessId() &&                                  //Our section can be mapped remotely into tis process - we don't need that
		CFunc::IsSuffixedUnicodeString(FullImageName, &kernel32) &&              //Need kernel32.dll only
		CFunc::IsMappedByLdrLoadDll(&kernel32)                                   //Make sure that it's a call from the LdrLoadDll() function
#if defined(_DEBUG) && defined(LIMIT_INJECTION_TO_PROC)		
		&& CFunc::IsSpecificProcessW(ProcessId, LIMIT_INJECTION_TO_PROC, FALSE)  //For debug build limit it to specific process only (for testing purposes)
#endif
		)
	{
#ifdef _WIN64
		//Is it a 32-bit process running in a 64-bit OS
		BOOLEAN bWowProc = IoIs32bitProcess(NULL);
#else
		//Cannot be a WOW64 process on a 32-bit OS
		BOOLEAN bWowProc = FALSE;
		UNREFERENCED_PARAMETER(bWowProc);
#endif

		//Now we can proceed with our injection
#ifdef DBG_VERBOSE_DRV
		DbgPrintLine("Image load (WOW=%d) for PID=%u: \"%wZ\"", bWowProc, (ULONG)(ULONG_PTR)ProcessId, FullImageName);
#endif


		//Get our (DLL) section to inject
		DLL_STATS* pDS;
		status = sec.GetSection(&pDS);
		if(NT_SUCCESS(status))
		{
			//And inject now
			status = sec.InjectDLL(pDS);
			if(!NT_SUCCESS(status))
			{
				//Error
				DbgPrintLine("ERROR: (0x%X) sec.InjectDLL, PID=%u", status, (ULONG)(ULONG_PTR)ProcessId);
			}
		}
		else
		{
			//Error
			DbgPrintLine("ERROR: (0x%X) sec.GetSection, PID=%u", status, (ULONG)(ULONG_PTR)ProcessId);
		}



		//The following only applies to a 64-bit build
		//INFO: We need to inject our DLL into a 32-bit process too...
#ifdef _WIN64
		if(bWowProc)
		{
			status = secWow.GetSection(&pDS);
			if(NT_SUCCESS(status))
			{
				//And inject now
				status = secWow.InjectDLL(pDS);
				if(!NT_SUCCESS(status))
				{
					//Error
					DbgPrintLine("ERROR: (0x%X) secWow.InjectDLL, PID=%u", status, (ULONG)(ULONG_PTR)ProcessId);
				}
			}
			else
			{
				//Error
				DbgPrintLine("ERROR: (0x%X) secWow.GetSection, PID=%u", status, (ULONG)(ULONG_PTR)ProcessId);
			}
		}
#endif

	}


}




NTSTATUS FreeResources()
{
	//Free our resources (must be called before unloading the driver)
	NTSTATUS status = STATUS_SUCCESS;

	//Remove the notification callback (only if it was set before)
	if(_bittestandreset((LONG*)&g_Flags, flImageNotifySet))
	{
		status = PsRemoveLoadImageNotifyRoutine(OnLoadImage);
		if(!NT_SUCCESS(status))
		{
			DbgPrintLine("CRITICAL: (0x%X) PsRemoveLoadImageNotifyRoutine", status);
		}
	}

	//Free our native section
	NTSTATUS status2 = sec.FreeSection();
	if(!NT_SUCCESS(status2))
	{
		//Error
		DbgPrintLine("ERROR: (0x%X) sec.FreeSection", status2);

		if(NT_SUCCESS(status))
			status = status2;
	}

#ifdef _WIN64
	//Free our WOW64 section
	status2 = secWow.FreeSection();
	if(!NT_SUCCESS(status2))
	{
		//Error
		DbgPrintLine("ERROR: (0x%X) secWow.FreeSection", status2);

		if(NT_SUCCESS(status))
			status = status2;
	}
#endif


	return status;
}






void NTAPI DriverUnload(PDRIVER_OBJECT DriverObject)
{
	//Routine that is called when driver is unloaded
	NTSTATUS status = FreeResources();

	DbgPrintLine("DriverUnload(0x%p), status=0x%x", DriverObject, status);
}




extern "C" NTSTATUS NTAPI DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	//Main driver entry routine
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	DbgPrintLine("DriverLoad(0x%p, %wZ)", DriverObject, RegistryPath);

	g_DriverObject = DriverObject;

	//Initialize our section object
	VERIFY(NT_SUCCESS(sec.Initialize(SEC_TP_NATIVE)));

#ifdef _WIN64
	//Initialize our WOW64 section object
	VERIFY(NT_SUCCESS(secWow.Initialize(SEC_TP_WOW)));
#endif

	DriverObject->DriverUnload = DriverUnload;

	//Set image-loading notification routine
	NTSTATUS status = PsSetLoadImageNotifyRoutine(OnLoadImage);
	if(NT_SUCCESS(status))
	{
		_bittestandset((LONG*)&g_Flags, flImageNotifySet);
	}
	else
	{
		//Error
		DbgPrintLine("CRITICAL: (0x%X) PsSetLoadImageNotifyRoutine", status);
	}

	return status;
}










