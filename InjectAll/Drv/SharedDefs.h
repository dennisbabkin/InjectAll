//Definitions that are shared across projects in this solution

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


#define DBG_PREFIX_ALL "InjectAll_"					//prefix to be added in all DbgPrint calls

#define INJECTED_DLL_FILE_NAME64 "FAKE64.DLL"		//File name of the injected 64-bit DLL (name only!)
#define INJECTED_DLL_FILE_NAME32 "FAKE32.DLL"		//File name of the injected 32-bit DLL (name only!)

#ifdef _WIN64
#define INJECTED_DLL_FILE_NAME INJECTED_DLL_FILE_NAME64
#else
#define INJECTED_DLL_FILE_NAME INJECTED_DLL_FILE_NAME32
#endif




// {9C74596E-7279-4FD9-9B8D-2CA5C7F9FDBE}
#define GUID_SearchTag_DllName_Bin 0x9C74596E, 0x7279, 0x4FD9, 0x9B, 0x8D, 0x2C, 0xA5, 0xC7, 0xF9, 0xFD, 0xBE











