//Driver custom types and definitions

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

#include <ntifs.h>
#include <minwindef.h>
#include <ntimage.h>
#include <ntstrsafe.h>

#include "SharedDefs.h"


//#define DBG_VERBOSE_DRV                          //Uncomment this line to make verbose debugging output for the driver's DEBUG build



#define DBG_PREFIX DBG_PREFIX_ALL "Drv: "          //Prefix to be added in all DbgPrint call in this project

#define DbgPrintLine(s, ...) DbgPrint(DBG_PREFIX s "\n", __VA_ARGS__)

//#define LIMIT_INJECTION_TO_PROC L"notepad.exe"   //Process to limit injection to (only in Debugger builds)




//Some debug build definitions
#ifdef DBG
#define _DEBUG DBG
#define VERIFY(f) ASSERT(f)
#else
#define VERIFY(f) ((void)(f))
#endif



enum IMAGE_LOAD_FLAGS
{
	flImageNotifySet,                //[set] when PsSetLoadImageNotifyRoutine was enabled
};



#define echo(x) x
#define label(x) echo(x)##__LINE__
#define RTL_CONSTANT_STRINGW_(s) { sizeof( s ) - sizeof( (s)[0] ), sizeof( s ), const_cast<PWSTR>(s) }

#define STATIC_UNICODE_STRING(name, str) \
static const WCHAR label(__)[] = echo(L)str;\
static const UNICODE_STRING name = RTL_CONSTANT_STRINGW_(label(__))

#define STATIC_OBJECT_ATTRIBUTES(oa, name)\
	STATIC_UNICODE_STRING(label(m), name);\
	static OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, const_cast<PUNICODE_STRING>(&label(m)), OBJ_CASE_INSENSITIVE }


//Flips kernel memory allocation pool tag around (for debuggers)
#define TAG(t) ( ((((ULONG)t) & 0xFF) << (8 * 3)) | ((((ULONG)t) & 0xFF00) << (8 * 1)) | ((((ULONG)t) & 0xFF0000) >> (8 * 1)) | ((((ULONG)t) & 0xFF000000) >> (8 * 3)) )



enum SECTION_TYPE{
	SEC_TP_NATIVE = 'n',     //Native section - meaning: 64-bit on a 64-bit OS, or 32-bit on a 32-bit OS
	SEC_TP_WOW = 'w',        //WOW64 section - meaning: 32-bit on a 64-bit OS
};



//Path where fake.dll is located on disk
//INFO: To make this injection work, the DLL must be placed in the appropriate System32 folder
//
#define INJECTED_DLL_NT_PATH_NTV "\\systemroot\\system32\\" INJECTED_DLL_FILE_NAME        //Native
#define INJECTED_DLL_NT_PATH_WOW "\\systemroot\\syswow64\\" INJECTED_DLL_FILE_NAME32      //WOW on a 64-bit OS


//Undocumented structs:
///////////////////////////////////////////////////////
enum SECTION_INFORMATION_CLASS
{
	SectionBasicInformation,
	SectionImageInformation
};

struct SECTION_IMAGE_INFORMATION
{
	PVOID TransferAddress;
	ULONG ZeroBits;
	SIZE_T MaximumStackSize;
	SIZE_T CommittedStackSize;
	ULONG SubSystemType;
	union
	{
		struct s
		{
			USHORT SubSystemMinorVersion;
			USHORT SubSystemMajorVersion;
		};
		ULONG SubSystemVersion;
	};
	ULONG GpValue;
	USHORT ImageCharacteristics;
	USHORT DllCharacteristics;
	USHORT Machine;
	BOOLEAN ImageContainsCode;
	union
	{
		UCHAR ImageFlags;
		struct u
		{
			UCHAR ComPlusNativeReady : 1;
			UCHAR ComPlusILOnly : 1;
			UCHAR ImageDynamicallyRelocated : 1;
			UCHAR ImageMappedFlat : 1;
			UCHAR BaseBelow4gb : 1;
			UCHAR Reserved : 3;
		};
	};
	ULONG LoaderFlags;
	ULONG ImageFileSize;
	ULONG CheckSum;
};


enum KAPC_ENVIRONMENT
{
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
};

typedef
VOID __stdcall
KNORMAL_ROUTINE(
	__in_opt PVOID NormalContext,
	__in_opt PVOID SystemArgument1,
	__in_opt PVOID SystemArgument2
);
typedef KNORMAL_ROUTINE* PKNORMAL_ROUTINE;

typedef
VOID __stdcall
KKERNEL_ROUTINE(
	__in struct _KAPC* Apc,
	__deref_inout_opt PKNORMAL_ROUTINE* NormalRoutine,
	__deref_inout_opt PVOID* NormalContext,
	__deref_inout_opt PVOID* SystemArgument1,
	__deref_inout_opt PVOID* SystemArgument2
);
typedef KKERNEL_ROUTINE* PKKERNEL_ROUTINE;

typedef
VOID __stdcall
KRUNDOWN_ROUTINE(
	__in struct _KAPC* Apc
);
typedef KRUNDOWN_ROUTINE* PKRUNDOWN_ROUTINE;

//End of Undocumented structs:
///////////////////////////////////////////////////////



//Undocumented functions:
///////////////////////////////////////////////////////
extern "C" {
	__declspec(dllimport) PIMAGE_NT_HEADERS RtlImageNtHeader(PVOID Base);
	__declspec(dllimport) PVOID RtlImageDirectoryEntryToData(PVOID Base, BOOLEAN MappedAsImage, USHORT DirectoryEntry, PULONG Size);

	__declspec(dllimport) BOOLEAN PsIsProcessBeingDebugged(PEPROCESS Process);

	__declspec(dllimport) NTSTATUS ZwQueryInformationProcess
	(
		IN HANDLE ProcessHandle,
		IN  PROCESSINFOCLASS ProcessInformationClass,
		OUT PVOID ProcessInformation,
		IN ULONG ProcessInformationLength,
		OUT PULONG ReturnLength OPTIONAL
	);

	__declspec(dllimport) void KeInitializeApc(
		IN PKAPC Apc,
		IN PKTHREAD Thread,
		IN KAPC_ENVIRONMENT ApcIndex,
		IN PKKERNEL_ROUTINE KernelRoutine,
		IN PKRUNDOWN_ROUTINE RundownRoutine,
		IN PKNORMAL_ROUTINE NormalRoutine,
		IN ULONG ApcMode,
		IN PVOID NormalContext
	);

	__declspec(dllimport) BOOLEAN KeInsertQueueApc(
		IN PKAPC Apc,
		IN PVOID SystemArgument1,
		IN PVOID SystemArgument2,
		IN ULONG PriorityIncrement
	);

	__declspec(dllimport) NTSTATUS ZwQuerySection(
		IN HANDLE SectionHandle, 
		IN ULONG SectionInformationClass, 
		OUT PVOID SectionInformation,
		IN ULONG SectionInformationLength,
		OUT PSIZE_T ResultLength OPTIONAL
	);

	__declspec(dllimport) NTSTATUS MmMapViewOfSection(
		IN PVOID SectionToMap,
		IN PEPROCESS Process,
		IN OUT PVOID* CapturedBase,
		IN ULONG_PTR ZeroBits,
		IN SIZE_T CommitSize,
		IN OUT PLARGE_INTEGER SectionOffset,
		IN OUT PSIZE_T CapturedViewSize,
		IN SECTION_INHERIT InheritDisposition,
		IN ULONG AllocationType,
		IN ULONG Protect
	);

	__declspec(dllimport) NTSTATUS MmUnmapViewOfSection(
		IN PEPROCESS Process,
		IN PVOID BaseAddress
	);

	__declspec(dllimport) BOOLEAN NTAPI KeTestAlertThread(IN KPROCESSOR_MODE AlertMode);

}
//End of Undocumented functions:
///////////////////////////////////////////////////////




#ifndef SEC_IMAGE
#define SEC_IMAGE 0x01000000
#endif







