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


#include "CSection.h"

#include "CFunc.h"			//Aux functions



extern "C" {
	extern PDRIVER_OBJECT g_DriverObject;

	//The following functions are defined in the Assembly file:
	void __stdcall RundownRoutine(PKAPC);
	void __stdcall KernelRoutine(PKAPC pApc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* NormalContext, PVOID* SystemArgument1, PVOID* SystemArgument2);
	void __stdcall NormalRoutine(PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2);
	//End of functions defined in the Assembly file



}



NTSTATUS CSection::Initialize(SECTION_TYPE type)
{
	//Initialize this object
	//INFO: Cannot use constructor/destructor!
	//'type' = type of section (or DLL) that this section will represent
	sectionType = type;

	//Initialize our singleton
	RtlRunOnceInitialize(&SectionSingletonState);

	return STATUS_SUCCESS;
}


NTSTATUS CSection::GetSection(DLL_STATS** ppOutSectionInfo)
{
	//Get DLL section object
	//INFO: Will create it only once, if it wasn't created earlier
	//'ppOutSectionInfo' = if not NULL, receives the section object info, or NULL if error
	//RETURN:
	//		= Status of operation
	NTSTATUS status = STATUS_SUCCESS;

	//Make sure that CSection::Initialize was called!
	ASSERT(sectionType == SEC_TP_NATIVE || sectionType == SEC_TP_WOW);

	//Use the singleton approach
	PVOID Context = NULL;
	status = RtlRunOnceBeginInitialize(&SectionSingletonState, 0, &Context);
	if(status == STATUS_PENDING)
	{
		//We get here only during the first initialization
		Context = NULL;

		//Alloc memory
		DLL_STATS* pDStats = (DLL_STATS*)ExAllocatePoolWithTag(ALLOC_TYPE_OnLoadImage, sizeof(DLL_STATS), TAG('kDSm'));
		if(pDStats)
		{
			//Need to "trick" the system into creating a KnownDll section for us with the SD of the kernel32.dll section

			//Temporarily attach the current thread to the address space of the system process
			KAPC_STATE as;
			KeStackAttachProcess(PsInitialSystemProcess, &as);

			//Create our KnownDll section
			status = CreateKnownDllSection(*pDStats);

			//Revert back
			KeUnstackDetachProcess(&as);


			//Check the result
			if(NT_SUCCESS(status))
			{
				//We'll keep the section info in the context
				Context = pDStats;
			}
			else
			{
				//Error
				DbgPrintLine("ERROR: (0x%x) CreateKnownDllSection, sectionType=%c", status, sectionType);

				//Free memory
				ExFreePool(pDStats);
				pDStats = NULL;
			}

		}
		else
		{
			//Error
			status = STATUS_MEMORY_NOT_ALLOCATED;
			DbgPrintLine("ERROR: (0x%x) ExAllocatePoolWithTag(kDSm), sectionType=%c", status, sectionType);
		}



		//Finalize our singleton
		NTSTATUS status2 = RtlRunOnceComplete(&SectionSingletonState, 0, Context);
		if(!NT_SUCCESS(status2))
		{
			//Error
			DbgPrintLine("ERROR: (0x%x) RtlRunOnceComplete, sectionType=%c", status2, sectionType);
			ASSERT(NULL);

			if(NT_SUCCESS(status))
				status = status2;

			if(pDStats)
			{
				//Free memory
				ExFreePool(pDStats);
				pDStats = NULL;
			}

			Context = NULL;
		}
	}
	else if(status != STATUS_SUCCESS)
	{
		//Error
		DbgPrintLine("ERROR: (0x%x) RtlRunOnceBeginInitialize, sectionType=%c", status, sectionType);
		ASSERT(NULL);
	}


	//Did we get the pointer?
	if(!Context &&
		status == STATUS_SUCCESS)
	{
		//We previously failed to create section
		status = STATUS_NONEXISTENT_SECTOR;
	}

	if(ppOutSectionInfo)
		*ppOutSectionInfo = (DLL_STATS*)Context;

	return status;
}



NTSTATUS CSection::FreeSection()
{
	//Release resources held for the mapped section
	//INFO: Doesn't do anything if GetSection() wasn't called yet
	//RETURN:
	//		= Status of the operations
	NTSTATUS status;

	PVOID Context = NULL;
	status = RtlRunOnceBeginInitialize(&SectionSingletonState, 0, &Context);
	if(NT_SUCCESS(status))
	{
		//We have initialized our singleton

		//Do we have the context - otherwise there's nothing to delete
		if(Context)
		{
			DLL_STATS* pDStats = (DLL_STATS*)Context;

#ifdef DBG_VERBOSE_DRV
			DbgPrintLine("FreeSection, sectionType=%c", sectionType);
#endif

			//Remove permanent flag from the section object
			ObMakeTemporaryObject(pDStats->Section);

			//And derefence it
			ObDereferenceObjectWithTag(pDStats->Section, TAG('hFkS'));
			pDStats->Section = NULL;


			//Free memory
			ExFreePool(Context);
			Context = NULL;
		}

		//Reset the singleton back
		RtlRunOnceInitialize(&SectionSingletonState);
	}
	else if(status == STATUS_UNSUCCESSFUL)
	{
		//GetSection() wasn't called yet
		status = STATUS_SUCCESS;
	}
	else
	{
		//Error
		DbgPrintLine("ERROR: (0x%x) FreeSection, sectionType=%c", status, sectionType);
		ASSERT(NULL);
	}

	return status;
}



NTSTATUS CSection::CreateKnownDllSection(DLL_STATS& outStats)
{
	//Create a known-DLL system section of our own
	//'outStatus' = receives information on created known section (only if return success)
	//RETURN:
	//		= Status of the operations
	NTSTATUS status;

	//Clear the returned data (assuming only primitive data types)
	memset(&outStats, 0, sizeof(outStats));


	POBJECT_ATTRIBUTES poaKernel32;
	PCUNICODE_STRING pstrFakeDll;
	PCOBJECT_ATTRIBUTES poaPathFakeDll;

#ifdef _WIN64
	if(sectionType == SEC_TP_WOW)
	{
		//32-bit section loaded on a 64-bit OS
		STATIC_OBJECT_ATTRIBUTES(oaKernel32, "\\KnownDlls32\\kernel32.dll");
		STATIC_UNICODE_STRING(strFakeDll, "\\KnownDlls32\\" INJECTED_DLL_FILE_NAME32);
		STATIC_OBJECT_ATTRIBUTES(oaPathFakeDll, INJECTED_DLL_NT_PATH_WOW);

		poaKernel32 = &oaKernel32;
		pstrFakeDll = &strFakeDll;
		poaPathFakeDll = &oaPathFakeDll;
	}
	else
#endif
	{
		//64-bit section loaded on a 64-bit OS, or
		//32-bit section loaded on a 32-bit OS
		STATIC_OBJECT_ATTRIBUTES(oaKernel32, "\\KnownDlls\\kernel32.dll");
		STATIC_UNICODE_STRING(strFakeDll, "\\KnownDlls\\" INJECTED_DLL_FILE_NAME);
		STATIC_OBJECT_ATTRIBUTES(oaPathFakeDll, INJECTED_DLL_NT_PATH_NTV);

		poaKernel32 = &oaKernel32;
		pstrFakeDll = &strFakeDll;
		poaPathFakeDll = &oaPathFakeDll;
	}


	//Need to "steal" a security descriptor from existing KnownDll - we'll use kernel32.dll
	HANDLE hSectionK32;
	status = ZwOpenSection(&hSectionK32, READ_CONTROL, const_cast<POBJECT_ATTRIBUTES>(poaKernel32));
	if(NT_SUCCESS(status))
	{
		status = STATUS_GENERIC_COMMAND_FAILED;

		//INFO: Make our section "permanent", which means that it won't be deleted if all of its handles are closed
		//      and we will need to call ZwMakeTemporaryObject() on it first to allow it
		OBJECT_ATTRIBUTES oaFakeDll = { sizeof(oaFakeDll), 0, 
			const_cast<PUNICODE_STRING>(pstrFakeDll),
			OBJ_CASE_INSENSITIVE | OBJ_PERMANENT };


		//Allocate needed memory
		ULONG uicbMemSz = 0;

		for(;;)
		{
			ULONG uicbMemNeededSz = 0;

			status = ZwQuerySecurityObject(hSectionK32, 
				PROCESS_TRUST_LABEL_SECURITY_INFORMATION |
				DACL_SECURITY_INFORMATION |
				LABEL_SECURITY_INFORMATION |
				OWNER_SECURITY_INFORMATION,
				oaFakeDll.SecurityDescriptor,		//SD
				uicbMemSz,							//mem size
				&uicbMemNeededSz);

			if(NT_SUCCESS(status))
			{
				//Got it
				break;
			}
			else if(status == STATUS_BUFFER_TOO_SMALL)
			{
				//Need more memory
				ASSERT(uicbMemNeededSz > uicbMemSz);

				if(oaFakeDll.SecurityDescriptor)
				{
					//Free previous memory
					ExFreePool(oaFakeDll.SecurityDescriptor);
				}

				//Allocate mem
				oaFakeDll.SecurityDescriptor = ExAllocatePoolWithTag(ALLOC_TYPE_OnLoadImage, uicbMemNeededSz, TAG('k32m'));
				if(oaFakeDll.SecurityDescriptor)
				{
					//Need to retry
					uicbMemSz = uicbMemNeededSz;
				}
				else
				{
					//Error
					status = STATUS_MEMORY_NOT_ALLOCATED;
					DbgPrintLine("ERROR: (0x%X) ExAllocatePoolWithTag(hSectionK32), PID=%u, sz=%u, sectionType=%c"
						,
						status,
						(ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
						uicbMemNeededSz,
						sectionType
					);

					break;
				}
			}
			else
			{
				//Error
				DbgPrintLine("ERROR: (0x%X) ZwQuerySecurityObject(hSectionK32), PID=%u, sz=%u, sectionType=%c"
					,
					status,
					(ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
					uicbMemSz,
					sectionType
				);

				break;
			}
		}


		//Close section
		VERIFY(NT_SUCCESS(ZwClose(hSectionK32)));

		if(NT_SUCCESS(status))
		{
			//Now we can create our own section for our injected DLL in the KnownDlls kernel object directory

			HANDLE hFile;
			IO_STATUS_BLOCK iosb;

			//Open existing DLL that we will be injecting
			status = ZwOpenFile(&hFile, FILE_GENERIC_READ | FILE_EXECUTE,
				const_cast<POBJECT_ATTRIBUTES>(poaPathFakeDll), &iosb, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);

			if(NT_SUCCESS(status))
			{
				//Open PE file as section
				HANDLE hFakeSection;
				status = ZwCreateSection(&hFakeSection, SECTION_MAP_EXECUTE | SECTION_QUERY,
					&oaFakeDll, 0, PAGE_EXECUTE, SEC_IMAGE, hFile);

				if(NT_SUCCESS(status))
				{
					//Map it into our process
					//INFO: We need two things:
					//		1. Get the offset of our shellcode - or UserModeNormalRoutine function
					//		2. Verify that this is our DLL and get its name from SEARCH_TAG_W
					PVOID BaseAddress = NULL;
					SIZE_T ViewSize = 0;
					status = ZwMapViewOfSection(hFakeSection, NtCurrentProcess(), &BaseAddress, 0, 0, 0,
						&ViewSize, ViewUnmap, 0, PAGE_READONLY);
					if(NT_SUCCESS(status))
					{
						//Need to look up our ordinal function, it will be our ShellCode that we will call later
						//INFO: It is located at the ordinal number 1 (it is defined in the .def file for that DLL exports)
						ASSERT(BaseAddress);
						ULONG OrdinalIndex = 1;
						ULONG uRVA = 0;

						__try
						{
							status = STATUS_INVALID_IMAGE_FORMAT;

							PIMAGE_NT_HEADERS pNtHdr = RtlImageNtHeader(BaseAddress);
							if(pNtHdr)
							{
								ULONG size;
								PIMAGE_EXPORT_DIRECTORY pExpDir = (PIMAGE_EXPORT_DIRECTORY)
									RtlImageDirectoryEntryToData(BaseAddress, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &size);

								if(pExpDir &&
									size >= sizeof(IMAGE_EXPORT_DIRECTORY))
								{
									OrdinalIndex -= pExpDir->Base;
									if(OrdinalIndex < pExpDir->NumberOfFunctions)
									{
										PULONG pAddressOfFunctions = (PULONG)((BYTE*)BaseAddress + pExpDir->AddressOfFunctions);

										if(pAddressOfFunctions)
										{
											//Get our needed SHellCode function's RVA
											uRVA = pAddressOfFunctions[OrdinalIndex];

											if(uRVA > 0)		//Our DLL is small - do this quick check
											{

												//Locate the offset of the search tag
												//INFO: It will give use the injected DLL name (it will be used for Shell Code later)
												static GUID guiSrch = { GUID_SearchTag_DllName_Bin };
												UINT uRVA_StchTag = CFunc::FindStringByTag(BaseAddress, 
													pNtHdr->OptionalHeader.SizeOfImage,
													&guiSrch);
												if(uRVA_StchTag != -1)
												{
													//Get information from our section
													SECTION_IMAGE_INFORMATION sii;
													status = ZwQuerySection(hFakeSection, SectionImageInformation, 
														&sii, sizeof(sii), 0);
													if(NT_SUCCESS(status))
													{


														//Get our section object pointer & increment its reference count
														status = ObReferenceObjectByHandleWithTag(hFakeSection, 0, NULL, 
															KernelMode, TAG('hFkS'), 
															&outStats.Section, NULL);

														if(NT_SUCCESS(status))
														{
															//Set return parameters
															outStats.secType = sectionType;
															outStats.SizeOfImage = pNtHdr->OptionalHeader.SizeOfImage;
															outStats.uRVA_ShellCode = uRVA;
															outStats.uRVA_DllName = uRVA_StchTag;

															//SECTION_IMAGE_INFORMATION::TransferAddress = address of entry point
															//       in the module after it was randomly relocated by ASLR
															outStats.PreferredAddress = (BYTE*)sii.TransferAddress - 
																pNtHdr->OptionalHeader.AddressOfEntryPoint;

#ifdef  DBG_VERBOSE_DRV
															DbgPrintLine(
																"KnownDll Created! PID=%u, RVA=0x%X, PreferredAddress=0x%p, sectionType=%c"
																,
																(ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
																uRVA,
																outStats.PreferredAddress,
																sectionType
															);
#endif

															//Done
															status = STATUS_SUCCESS;
														}
														else
														{
															//Error
															DbgPrintLine("ERROR: (0x%X) ObReferenceObjectByHandle, PID=%u, sectionType=%c"
																,
																status,
																(ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
																sectionType
															);
														}
													}
													else
													{
														//Error
														DbgPrintLine("ERROR: (0x%X) ZwQuerySection, PID=%u, sectionType=%c"
															,
															status,
															(ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
															sectionType
														);
													}
												}
												else
												{
													//Error
													DbgPrintLine(
														"ERROR: (0x%X) FindStringByTag, PID=%u, base=0x%p, sz=%u, sectionType=%c"
														,
														status,
														(ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
														BaseAddress,
														pNtHdr->OptionalHeader.SizeOfImage,
														sectionType
													);
												}
											}
											else
											{
												//Error
												DbgPrintLine("ERROR: (0x%X) Bad RVA=%d, PID=%u, sectionType=%c"
													,
													status,
													uRVA,
													(ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
													sectionType
												);
											}
										}
										else
										{
											//Error
											DbgPrintLine("ERROR: (0x%X) Bad AddressOfFunctions, PID=%u, sectionType=%c"
												,
												status,
												(ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
												sectionType
											);
										}
									}
									else
									{
										//Error
										DbgPrintLine("ERROR: (0x%X) Bad ordinal, PID=%u cnt=%u, sectionType=%c"
											,
											status,
											(ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
											pExpDir->NumberOfFunctions,
											sectionType
										);
									}
								}
								else
								{
									//Error
									DbgPrintLine("ERROR: (0x%X) Export directory, PID=%u size=%u, sectionType=%c"
										,
										status,
										(ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
										size,
										sectionType
									);
								}
							}
							else
							{
								//Error
								DbgPrintLine("ERROR: (0x%X) RtlImageNtHeader, PID=%u, sectionType=%c"
									,
									status,
									(ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
									sectionType
								);
							}
						}
						__except(EXCEPTION_EXECUTE_HANDLER)
						{
							//Failed to parse PE file
							DbgPrintLine("#EXCEPTION: (0x%X) CreateKnownDllSection(PE-scan), PID=%u, sectionType=%c"
								,
								GetExceptionCode(),
								(ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
								sectionType
							);

							status = STATUS_INVALID_IMAGE_FORMAT;
						}


						//Unmap the section
						VERIFY(NT_SUCCESS(ZwUnmapViewOfSection(NtCurrentProcess(), BaseAddress)));
					}
					else
					{
						//Error
						DbgPrintLine("ERROR: (0x%X) ZwMapViewOfSection, PID=%u, sectionType=%c"
							,
							status,
							(ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
							sectionType
						);
					}




					//Did we fail setting the section up?
					if(!NT_SUCCESS(status))
					{
						//Make it not permanent (so that we can remove)
						VERIFY(NT_SUCCESS(ZwMakeTemporaryObject(hFakeSection)));
					}

					//Close our section
					VERIFY(NT_SUCCESS(ZwClose(hFakeSection)));
				}
				else
				{
					//Error
					DbgPrintLine("ERROR: (0x%X) ZwCreateSection, PID=%u, sectionType=%c"
						,
						status,
						(ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
						sectionType
					);
				}


				//Close file
				VERIFY(NT_SUCCESS(ZwClose(hFile)));
			}
			else
			{
				//Error
				DbgPrintLine("ERROR: (0x%X) ZwOpenFile, PID=%u, sectionType=%c, path=\"%wZ\""
					,
					status,
					(ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
					sectionType,
					poaPathFakeDll->ObjectName
				);
			}
		}


		//Free our memory
		if(oaFakeDll.SecurityDescriptor)
		{
			ExFreePool(oaFakeDll.SecurityDescriptor);
			oaFakeDll.SecurityDescriptor = NULL;
		}

	}
	else
	{
		//Error
		DbgPrintLine("ERROR: (0x%X) ZwOpenSection(hSectionK32), PID=%u, sectionType=%c"
			,
			status,
			(ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
			sectionType
		);
	}


	return status;
}





NTSTATUS CSection::InjectDLL(DLL_STATS* pDllStats)
{
	//Inject DLL into the current process
	//'pDllStats' = DLL info to inject
	ASSERT(pDllStats);
	NTSTATUS status;

	//Sanity check
	if(!pDllStats->IsValid())
	{
		//Invalid data
		ASSERT(NULL);
		return STATUS_INVALID_PARAMETER_MIX;
	}

	//We need to allocate our KAPC from NonPagedPool. For details check:
	//	https://dennisbabkin.com/blog/?i=AAA03000#kernel_apc_memory
	//
	PKAPC pApc = (PKAPC)ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), TAG('apc1'));
	if(!pApc)
	{
		//Failed to allocate mem
		return STATUS_MEMORY_NOT_ALLOCATED;
	}


	//Because we're called from under a critical section during the OnLoadImage callback,
	//initialize an APC to do all the work for us later ...
	//
	//INFO:
	//      KernelRoutine = must be provided. It runs first at APC IRQL.
	//      NormalRoutine = [optional] Is called after KernelRoutine at PASSIVE IRQL.
	//      RundownRoutine = [optional] runs only if thread was closed before it had a chance 
	//                                  to run and it had pending APCs. Otherwise it's not called.
	//                                  If RundownRoutine is called, neither KernelRoutine nor 
	//                                  NormalRoutine are called.

	//The reason we are coding KernelRoutine, RundownRoutine, NormalRoutine the way we did:
	//	https://dennisbabkin.com/blog/?i=AAA03000#pslinr_gotcha
	//

	//Set up "regular" kernel APC (since we specified NormalRoutine and KernelMode)
	KeInitializeApc(pApc, KeGetCurrentThread(),
		OriginalApcEnvironment,
		KernelRoutine, RundownRoutine, NormalRoutine,     //These routines are implemented in Assembly language - see asm64.asm or asm32.asm
		KernelMode,                                       //Kernel APC
		pApc                                              //Pass PKAPC as context into NormalRoutine
		);

	//Prevent our driver from unloading be incrementing its reference count
	ObReferenceObject(g_DriverObject);

	//Also keep our section object loaded
	ObReferenceObject(pDllStats->Section);


	//And initialize the APC
	if(KeInsertQueueApc(pApc,
		pDllStats,					//SystemArgument1 = points to DLL_STATS
		NULL,						//SystemArgument2 = not used
		IO_NO_INCREMENT))
	{
		//Queued APC OK
		status = STATUS_SUCCESS;
	}
	else
	{
		//Failed - do roll back
		status = STATUS_BAD_DATA;
		DbgPrintLine("ERROR: (0x%X) KeInsertQueueApc, PID=%u, sectionType=%c"
			,
			status,
			(ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
			sectionType
		);

		//Deference our objects
		ObDereferenceObject(pDllStats->Section);
		ObDereferenceObject(g_DriverObject);

		//Free mem
		ExFreePool(pApc);
		pApc = NULL;
	}


	return status;
}




extern "C" BOOL __stdcall RundownRoutine_Proc(PKAPC pApc)
{
	//Called from the asm64.asm/asm32.asm file for the RundownRoutine() call back
	//INFO: 
	//         runs only if thread was closed before it had a chance 
	//         to run and it had pending APCs. Otherwise it's not called.
	//         If RundownRoutine is called, neither KernelRoutine nor 
	//         NormalRoutine are called.
	//RETURN:
	//		= TRUE to invoke safely ObDereferenceObject(g_DriverObject)
	ASSERT(pApc);

#ifdef DBG_VERBOSE_DRV
	DbgPrintLine("RundownRoutine: IRQL=%u, PID=%u, APC=0x%p, mode=%d"
		,
		KeGetCurrentIrql(),
		(ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
		pApc,
		pApc->ApcMode
	);
#endif

	if(pApc)
	{
		//Free mem
		ExFreePool(pApc);
		pApc = NULL;
	}

	//Derefence driver object
	return TRUE;
}



extern "C" BOOL __stdcall KernelRoutine_Proc(PKAPC pApc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* NormalContext, PVOID* SystemArgument1, PVOID* SystemArgument2)
{
	//Called from the asm64.asm/asm32.asm file for the KernelRoutine() call back
	//INFO:
	//		It runs first at APC IRQL before NormalRoutine(). You may adjust parameters passed here fro the NormalRoutine
	//RETURN:
	//		= TRUE to invoke safely ObDereferenceObject(g_DriverObject)
	UNREFERENCED_PARAMETER(pApc);
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	ASSERT(pApc);
	BOOL bDerefDriverObject = TRUE;

#ifdef DBG_VERBOSE_DRV
	DbgPrintLine("KernelRoutine: IRQL=%u, PID=%u, APC=0x%p, mode=%d"
		,
		KeGetCurrentIrql(),
		(ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
		pApc,
		pApc->ApcMode
	);
#endif

	if(pApc->ApcMode == KernelMode)
	{
		//Kernel mode APC

		//Do not dereference driver object
		bDerefDriverObject = FALSE;
	}
	else if(pApc->ApcMode == UserMode)
	{
		//User-mode APC

		//Free mem
		ExFreePool(pApc);
		pApc = NULL;
	}
	else
	{
		//Something else?
		ASSERT(NULL);
	}


	return bDerefDriverObject;
}



extern "C" BOOL __stdcall NormalRoutine_Proc(PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
	//Called from the asm64.asm/asm32.asm file for the NormalRoutine() call back
	//INFO:
	//		It is called after KernelRoutine() at PASSIVE IRQL.
	//RETURN:
	//		= TRUE to invoke safely ObDereferenceObject(g_DriverObject)
	UNREFERENCED_PARAMETER(SystemArgument2);

	PKAPC pApc = (PKAPC)NormalContext;
	ASSERT(pApc);
	DLL_STATS* pDllStats = (DLL_STATS*)SystemArgument1;
	ASSERT(pDllStats);
	ASSERT(pDllStats->IsValid());


#ifdef DBG_VERBOSE_DRV
	DbgPrintLine("NormalRoutine: IRQL=%u, PID=%u, APC=0x%p, mode=%d, sectionType=%c"
		,
		KeGetCurrentIrql(),
		(ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
		pApc,
		pApc->ApcMode,
		pDllStats->secType
	);
#endif


	//INFO:
	//      Our FAKE.dll contains two types of code inside of it:
	//          - Shell-code = small function written in Assembly language, that is used to inject our FAKE.dll from the user-mode
	//                         (it does not require relocation and can run at any base address)
	//          - FAKE.dll = module itself that is being injected. The code that runs after injection is in DllMain.
	//                        It is important to note that if our injected Dll fails to map at its PreferredAddress, 
	//                        this will make the loader return STATUS_RETRY
	//                        and then insert a new work task (via LdrpRetryQueue) and retry to load it later using the DLL's 
	//                        full image path instead of the KnownDll section.
	//                        Thus we need to make sure that our injected DLL is mapped at the PreferredAddress!

	//Map the section to execute our Shell-code
	PVOID BaseAddress = 0;
	NTSTATUS status = CSection::MapSectionForShellCode(pDllStats, &BaseAddress);

	//Dereference section object after we're done with it
	//INFO: Since it's set as a permanent object it won't be unloaded yet
	ObDereferenceObject(pDllStats->Section);

	if(NT_SUCCESS(status))
	{
		//Our shell-code was mapped!

#ifdef _DEBUG
		char buffDbg[GCPFN_BUFF_SIZE];
		DbgPrintLine("Shell-code mapped: (0x%X) PID=%u: \"%S\", BaseAddr=0x%p, sectionType=%c"
			,
			status,
			(ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
			CFunc::debugGetCurrentProcName(buffDbg, sizeof(buffDbg), TRUE),
			BaseAddress,
			pDllStats->secType
		);
#endif

		//Define our user-mode normal routine, which is UserModeNormalRoutine function
		ASSERT(pDllStats->uRVA_ShellCode);
		PKNORMAL_ROUTINE p_umNormalRoutine = (PKNORMAL_ROUTINE)((BYTE*)BaseAddress + pDllStats->uRVA_ShellCode);

		//Calculate pointer to the inject DLL name in user-mode address space
		//INFO: Such DLL must be placed in the System32 folder of the appropriate bitness
		ASSERT(pDllStats->uRVA_DllName);
		PVOID p_umDllName = (PVOID)((BYTE*)BaseAddress + pDllStats->uRVA_DllName);


#ifdef _WIN64
		//For WOW64 section only
		if(pDllStats->secType == SEC_TP_WOW)
		{
			//Instruct 64-bit version of NTDLL to use APC callback in the 32-bit NTDLL
			PsWrapApcWow64Thread(&BaseAddress, (PVOID*)&p_umNormalRoutine);
		}
#endif




		//Set up user-mode APC that will do the injection for us
		ASSERT(BaseAddress);
		KeInitializeApc(pApc, KeGetCurrentThread(),
			OriginalApcEnvironment,
			KernelRoutine, RundownRoutine, p_umNormalRoutine,      //These routines are implemented in Assembly language - see asm64.asm or asm32.asm
			UserMode,                                              //User-mode APC
			BaseAddress                                            //Pass BaseAddress as context into normal routine
			);

		//Prevent our driver from unloading since we're queuing another APC
		ObReferenceObject(g_DriverObject);

		//And initialize the APC
		if(KeInsertQueueApc(pApc,
			p_umDllName,                //SystemArgument1 = points to injected DLL name as const WCHAR* (null terminated)
			NULL,                       //SystemArgument2 = not used
			IO_NO_INCREMENT))
		{
			//Queued APC OK

			//Force the call to the user-mode APC
			//INFO: It will be handled by the UserModeNormalRoutine() function in the dll_asm64.asm/dll_asm32.asm files
			KeTestAlertThread(UserMode);

			//Derefence driver object
			return TRUE;
		}
		else
		{
			//Error
			status = STATUS_BAD_DATA;
			DbgPrintLine("ERROR: (0x%X) NormalRoutine > KeInsertQueueApc, PID=%u, sectionType=%c"
				,
				status,
				(ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
				pDllStats->secType
			);

			//Reverse reference count
			ObDereferenceObject(g_DriverObject);

			//And unmap section with shell-code
			ASSERT(BaseAddress);
			VERIFY(NT_SUCCESS(MmUnmapViewOfSection(IoGetCurrentProcess(), BaseAddress)));
		}

	}
	else
	{
		//Error
		DbgPrintLine("ERROR: (0x%X) MapSectionForShellCode, PID=%u, sectionType=%c"
			,
			status,
			(ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
			pDllStats->secType
		);
	}


	//Free mem
	ExFreePool(pApc);
	pApc = NULL;


	//Derefence driver object
	return TRUE;
}




NTSTATUS CSection::MapSectionForShellCode(DLL_STATS* pDllStats, PVOID* pOutBaseAddr)
{
	//Map section to run our Shell-code in into the current process
	//INFO: The goal here is NOT to map it at its PreferredAddress, as otherwise it will conflict with loading
	//      of the FAKE.DLL itself that we are injecting ...
	//'pDllStats' = stats for the injected DLL
	//'pOutBaseAddr' = if not NULL, will receive base address where DLL was mapped for Shell-Code, or NULL if error
	//RETURN:
	//		= Status code of the operation
	//			IMPORTANT: Upon success the 'pDllStats->Section' will be mapped and needs to be unmapped
	//			           later with *UnmapViewOfSection!
	ASSERT(pDllStats);
	NTSTATUS status;
	
	PVOID BaseAddress = NULL;

	if(pDllStats->IsValid())
	{
		//Try to reserve memory at the PreferredAddress that we have for our injected DLL
		//INFO: This should ensure that we map our section at a different address later ...
		ASSERT(pDllStats->PreferredAddress);
		PVOID ReservedAddress = pDllStats->PreferredAddress;
		SIZE_T RegionSize = pDllStats->SizeOfImage;

		NTSTATUS status2 = ZwAllocateVirtualMemory(NtCurrentProcess(), 
			&ReservedAddress, 0, &RegionSize, MEM_RESERVE, PAGE_NOACCESS);

		//INFO: We get STATUS_CONFLICTING_ADDRESSES if there's something else at the ReservedAddress already
		if(status2 != STATUS_SUCCESS &&
			status2 != STATUS_CONFLICTING_ADDRESSES)
		{
			//Failed for some reason?
			DbgPrintLine("ERROR: (0x%X) MapSectionForShellCode > ZwAllocateVirtualMemory, PID=%u, sectionType=%c, "
				"addr=0x%p, sz=0x%X"
				,
				status2,
				(ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
				pDllStats->secType,
				pDllStats->PreferredAddress,
				pDllStats->SizeOfImage
			);
		}


		//Then map our section (at any address as our Shell-code doesn't care)
		ASSERT(pDllStats->Section);
		SIZE_T ViewSize = 0;
		LARGE_INTEGER Offset = {};

		status = MmMapViewOfSection(pDllStats->Section, IoGetCurrentProcess(), &BaseAddress, 0, 0,
			&Offset, &ViewSize, ViewUnmap, 0, PAGE_EXECUTE);

		if(!NT_SUCCESS(status))
		{
			//Error
			DbgPrintLine("ERROR: (0x%X) MapSectionForShellCode > MmMapViewOfSection, PID=%u, sectionType=%c"
				,
				status,
				(ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
				pDllStats->secType
			);
		}


		if(NT_SUCCESS(status2))
		{
			//Free memory chunk that we allocated above
			RegionSize = 0;
			VERIFY(NT_SUCCESS(ZwFreeVirtualMemory(NtCurrentProcess(), &ReservedAddress, &RegionSize, MEM_RELEASE)));
		}
	}
	else
	{
		//Error
		ASSERT(NULL);
		status = STATUS_INVALID_PARAMETER_MIX;
	}

	if(pOutBaseAddr)
		*pOutBaseAddr = BaseAddress;

	return status;
}





