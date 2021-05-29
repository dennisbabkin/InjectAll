//This C file is required to add CFG and some other security-related features into our PE file
//INFO: Otherwise our DLL may be rejected to be loaded into some processes ...
//

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


//SOURCE:
//      https://github.com/rbmm/INJECT/blob/master/loadcfg/loadcfg.c
//
//      https://docs.microsoft.com/en-us/cpp/build/reference/safeseh-image-has-safe-exception-handlers?view=msvc-160
//

#include <Windows.h>



//Replacements for CRT's global functions and variables
uintptr_t __security_cookie;            // /GS security cookie

void __fastcall __security_check_cookie(__in uintptr_t _StackCookie)
{
    if (__security_cookie != _StackCookie)
    {
        __debugbreak();
    }
}


void __fastcall _guard_check_icall_nop(_In_ PVOID /*Target*/);


extern const volatile PVOID __guard_check_icall_fptr = _guard_check_icall_nop;

#if defined(_AMD64_)
void _guard_dispatch_icall_nop();
extern const volatile PVOID __guard_dispatch_icall_fptr = _guard_dispatch_icall_nop;
#endif


#if defined(_M_IX86) || defined(_X86_)
/*
 * The following two names are automatically created by the linker for any
 * image that has the safe exception table present.
 */

extern PVOID __safe_se_handler_table[]; /* base of safe handler entry table */
extern BYTE  __safe_se_handler_count;   /* absolute symbol whose address is
                                           the count of table entries */
#endif

extern PVOID __guard_fids_table[];
extern ULONG __guard_fids_count;
extern ULONG __guard_flags;
extern PVOID __guard_iat_table[];
extern ULONG __guard_iat_count;
extern PVOID __guard_longjmp_table[];
extern ULONG __guard_longjmp_count;
extern PVOID __dynamic_value_reloc_table;
extern PVOID __enclave_config;


#if defined(_CHPE_X86_ARM64_)

extern const PVOID __chpe_metadata;

#endif

extern
const
IMAGE_LOAD_CONFIG_DIRECTORY
_load_config_used = {
    sizeof(_load_config_used),
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    (SIZE_T)&__security_cookie,

#if defined(_M_IX86) || defined(_X86_)

    (SIZE_T)__safe_se_handler_table,
    (SIZE_T)&__safe_se_handler_count,

#else

    0,
    0,

#endif

    (SIZE_T)&__guard_check_icall_fptr,

#if defined(_AMD64_)

    (SIZE_T)&__guard_dispatch_icall_fptr,

#else

    0,

#endif

    (SIZE_T)&__guard_fids_table,
    (SIZE_T)&__guard_fids_count,

    (ULONG)(SIZE_T)&__guard_flags,

};


