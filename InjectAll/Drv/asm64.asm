;  
;    Test solution that demonstrates DLL injection into all running processes
;    Copyright (c) 2021 www.dennisbabkin.com
;
;        https://dennisbabkin.com/blog/?i=AAA10800
;
;    Credit: Rbmm
;
;        https://github.com/rbmm/INJECT
;
;    Licensed under the Apache License, Version 2.0 (the "License");
;    you may not use this file except in compliance with the License.
;    You may obtain a copy of the License at
;    
;        https://www.apache.org/licenses/LICENSE-2.0
;    
;    Unless required by applicable law or agreed to in writing, software
;    distributed under the License is distributed on an "AS IS" BASIS,
;    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
;    See the License for the specific language governing permissions and
;    limitations under the License.
;  
;

.code

EXTERN g_DriverObject : QWORD
EXTERN __imp_ObfDereferenceObject : QWORD

EXTERN RundownRoutine_Proc : PROC
EXTERN KernelRoutine_Proc : PROC
EXTERN NormalRoutine_Proc : PROC



; VOID __stdcall KRUNDOWN_ROUTINE(_KAPC* Apc)
; 
RundownRoutine PROC
	; RCX = pointer to _KAPC

	; First call our RundownRoutine_Proc from the C file
	sub		rsp, 28h
	call	RundownRoutine_Proc
	add		rsp, 28h

	; Act depending on return value
	test	rax, rax
	jz		@@1

	; Then invoke ObDereferenceObject(g_DriverObject)
	; 
	; IMPORTANT: We need to invoke ObfDereferenceObject via a JMP because it will be freeing the driver
	;            memory that our code runs from, thus can't return into it via a CALL instruction!
	;
	mov		rcx, g_DriverObject
	jmp		__imp_ObfDereferenceObject

@@1:
	ret
RundownRoutine ENDP






; VOID __stdcall KKERNEL_ROUTINE(_KAPC* Apc, PVOID NormalRoutine, PVOID* NormalContext, PVOID* SystemArgument1, PVOID* SystemArgument2)
;
KernelRoutine PROC
	; RCX         = pointer to _KAPC
	; RDX         = pointer to NormalRoutine
	; R8          = pointer to NormalContext
	; R9          = pointer to SystemArgument1
	; [RSP + 28h] = pointer to SystemArgument2

	; Move SystemArgument2 for the forwarded call to KernelRoutine_Proc
	mov		rax, [rsp + 28h]
	mov		[rsp + 18h], rax

	; Save our return address in the shadow stack
	mov		rax, [rsp]
	mov		[rsp + 20h], rax


    ; During call to KernelRoutine:                   During call to KernelRoutine_Proc:
	; 
    ;                                                 RSP:
    ;                                                 -10h = return address from KernelRoutine_Proc
    ; RSP:                                            -08h =  - shadow stack
    ; +00h = return address from KernelRoutine        +00h =  - shadow stack
    ; +08h =  - shadow stack                          +08h =  - shadow stack
    ; +10h =  - shadow stack                          +10h =  - shadow stack
    ; +18h =  - shadow stack                          +18h = pointer to SystemArgument2
    ; +20h =  - shadow stack                          +20h = (saved return addr)
    ; +28h = pointer to SystemArgument2


	; Align stack pointer on the 16-byte boundary for the KernelRoutine_Proc call (and restore it afterwards)
	;	push rax = 8 bytes
	;	call	 = 8 bytes
	push	rax
	call	KernelRoutine_Proc
	test	rax, rax
	pop		rax

	; Restore our return address 
	mov		rax, [rsp + 20h]
	mov		[rsp], rax

	; Act depending on return value from function
	jz		@@1

	; Then invoke ObDereferenceObject(g_DriverObject)
	; 
	; IMPORTANT: We need to invoke ObfDereferenceObject via a JMP because it will be freeing the driver
	;            memory that our code runs from, thus can't return into it via a CALL instruction!
	;
	mov		rcx, g_DriverObject
	jmp		__imp_ObfDereferenceObject

@@1:
	ret
KernelRoutine ENDP





; VOID __stdcall KNORMAL_ROUTINE(PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2)
;
NormalRoutine PROC
	; RCX = NormalContext
	; RDX = SystemArgument1
	; R8  = SystemArgument2

	; First call our NormalRoutine_Proc from C file
	sub		rsp, 28h
	call	NormalRoutine_Proc
	add		rsp, 28h

	; Act depending on return value from function
	test	rax, rax
	jz		@@1

	; Then invoke ObDereferenceObject(g_DriverObject)
	; 
	; IMPORTANT: We need to invoke ObfDereferenceObject via a JMP because it will be freeing the driver
	;            memory that our code runs from, thus can't return into it via a CALL instruction!
	;
	mov		rcx, g_DriverObject
	jmp		__imp_ObfDereferenceObject

@@1:
	ret
NormalRoutine ENDP



END



