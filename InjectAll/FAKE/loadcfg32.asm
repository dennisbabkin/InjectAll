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


.686p
.model flat

.code



; The following are quick-and-dirty replacements for the CFG functions

@_guard_check_icall_nop@4 PROC
	ret
@_guard_check_icall_nop@4 ENDP



END


