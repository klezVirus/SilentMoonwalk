;   ------------------------------------------------------------------------------------
;
;   Author       : klezVirus 2022
;   Twitter      : https://twitter.com/klezVirus
;   Original Idea: Namazso 
;   Twitter      : https://twitter.com/namazso
;   ------------------------------------------------------------------------------------
;   ------------------------------------------------------------------------------------

spoof_call proto
restore proto

.data

;   ------------------------------------------------------------------------------------
; 	Spoofing Configuration Structure
;   Utility structure to pass all the relevant details from C to ASM regarding the 
;   stack frames to spoof
;   ------------------------------------------------------------------------------------
SPOOFER STRUCT

    KernelBaseAddress               DQ 1
    KernelBaseAddressEnd            DQ 1
    
    RtlUserThreadStartAddress       DQ 1
    BaseThreadInitThunkAddress      DQ 1

    FirstFrameFunctionPointer       DQ 1
    SecondFrameFunctionPointer      DQ 1
    JmpRbxGadget                    DQ 1
    AddRspXGadget                   DQ 1

    FirstFrameSize                  DQ 1
    FirstFrameRandomOffset          DQ 1
    SecondFrameSize                 DQ 1
    SecondFrameRandomOffset         DQ 1
    JmpRbxGadgetFrameSize           DQ 1
    AddRspXGadgetFrameSize          DQ 1

    RtlUserThreadStartFrameSize     DQ 1
    BaseThreadInitThunkFrameSize    DQ 1

    StackOffsetWhereRbpIsPushed     DQ 1

    JmpRbxGadgetRef                 DQ 1
    SpoofFunctionPointer            DQ 1
    ReturnAddress                   DQ 1

    Nargs                           DQ 1
    Arg01                           DQ 1
    Arg02                           DQ 1
    Arg03                           DQ 1
    Arg04                           DQ 1
    Arg05                           DQ 1
    Arg06                           DQ 1
    Arg07                           DQ 1
    Arg08                           DQ 1

SPOOFER ENDS

.code

get_current_rsp proc
	mov rax, rsp
    add rax, 8
    ret
get_current_rsp endp

spoof_call proc
;   ------------------------------------------------------------------------------------
;   Saving non-vol registers
;   ------------------------------------------------------------------------------------
	mov     [rsp+08h], rbp
	mov     [rsp+10h], rbx
;   ------------------------------------------------------------------------------------
;   Creating a stack reference to the JMP RBX gadget
;   ------------------------------------------------------------------------------------
	mov		rbx, [rcx].SPOOFER.JmpRbxGadget
	mov     [rsp+18h], rbx
	mov		rbx, rsp
	add		rbx, 18h
	mov		[rcx].SPOOFER.JmpRbxGadgetRef, rbx
;   ------------------------------------------------------------------------------------
;   Prolog
;   RBP -> Keeps track of original Stack
; 	RSP -> Desync Stack for Unwinding Info
;   ------------------------------------------------------------------------------------
;   Note: Everything between RSP and RBP is our new stack frame for unwinding 
;   ------------------------------------------------------------------------------------
	mov     rbp, rsp

;   ------------------------------------------------------------------------------------
;   Creating stack pointer to Restore PROC
;   ------------------------------------------------------------------------------------
	lea     rax, restore
	push    rax

;   Now RBX contains the stack pointer to Restore PROC  
;   -> Will be called by the JMP [RBX] gadget
	lea     rbx, [rsp]

;   ------------------------------------------------------------------------------------
;   Starting Frames Tampering
;   ------------------------------------------------------------------------------------

;   First Frame (Fake origin)
;   ------------------------------------------------------------------------------------
	push    [rcx].SPOOFER.FirstFrameFunctionPointer
	mov     rax, [rcx].SPOOFER.FirstFrameRandomOffset
	add     qword ptr [rsp], rax                                      
	
	mov     rax, [rcx].SPOOFER.ReturnAddress
	sub     rax, [rcx].SPOOFER.FirstFrameSize
	
	sub     rsp, [rcx].SPOOFER.SecondFrameSize
	mov     r10, [rcx].SPOOFER.StackOffsetWhereRbpIsPushed
	mov     [rsp+r10], rax
;   ------------------------------------------------------------------------------------
;   ROP Frames
;   ------------------------------------------------------------------------------------
	push    [rcx].SPOOFER.SecondFrameFunctionPointer
    mov     rax, [rcx].SPOOFER.SecondFrameRandomOffset
    add     qword ptr [rsp], rax
;   ------------------------------------------------------------------------------------
;   	1. JMP [RBX] Gadget
;   ------------------------------------------------------------------------------------
	sub     rsp, [rcx].SPOOFER.JmpRbxGadgetFrameSize
	push    [rcx].SPOOFER.JmpRbxGadgetRef
	sub     rsp, [rcx].SPOOFER.AddRspXGadgetFrameSize
	mov     r10, [rcx].SPOOFER.JmpRbxGadget
	mov     [rsp+38h], r10
;   ------------------------------------------------------------------------------------
;   	2. Stack PIVOT (To restore original Control Flow Stack)
;   ------------------------------------------------------------------------------------
	push    [rcx].SPOOFER.AddRspXGadget
	mov     rax, [rcx].SPOOFER.AddRspXGadgetFrameSize
	mov		[rbp+28h], rax
;   ------------------------------------------------------------------------------------
;   Set the pointer to the function to call in RAX
;   ------------------------------------------------------------------------------------
	mov     rax, [rcx].SPOOFER.SpoofFunctionPointer
	jmp     parameter_handler
	jmp 	execute
spoof_call endp
	
restore proc
	mov     rsp, rbp
	mov     rbp, [rsp+08h]
	mov     rbx, [rsp+10h]
	ret
restore endp

parameter_handler proc
	mov		r9, rax
	mov		rax, 8
	mov		r8, [rcx].SPOOFER.Nargs	
	mul		r8
;	pop		rdx
;	sub		rsp, rax -- Not necessary
;	push	rdx
	xchg	r9, rax
	cmp		[rcx].SPOOFER.Nargs, 8
	je		handle_eight
	cmp		[rcx].SPOOFER.Nargs, 7
	je		handle_seven
	cmp		[rcx].SPOOFER.Nargs, 6
	je		handle_six
	cmp		[rcx].SPOOFER.Nargs, 5
	je		handle_five
	cmp		[rcx].SPOOFER.Nargs, 4
	je		handle_four
	cmp		[rcx].SPOOFER.Nargs, 3
	je		handle_three
	cmp		[rcx].SPOOFER.Nargs, 2
	je		handle_two
	cmp		[rcx].SPOOFER.Nargs, 1
	je 		handle_one
	cmp		[rcx].SPOOFER.Nargs, 0
	je 		handle_none
parameter_handler endp

handle_eight proc
	push	r15
	mov		r15, [rcx].SPOOFER.Arg08
	mov		[rsp+48h], r15
	pop		r15
	jmp		handle_seven
handle_eight endp
handle_seven proc
	push	r15
	mov		r15, [rcx].SPOOFER.Arg07
	mov		[rsp+40h], r15
	pop		r15
	jmp		handle_six
handle_seven endp
handle_six proc
	push	r15
	mov		r15, [rcx].SPOOFER.Arg06
	mov		[rsp+38h], r15
	pop		r15
	jmp		handle_five
handle_six endp
handle_five proc
	push	r15
	mov		r15, [rcx].SPOOFER.Arg05
	mov		[rsp+30h], r15
	pop		r15
	jmp		handle_four
handle_five endp
handle_four proc
	mov		r9, [rcx].SPOOFER.Arg04
	jmp		handle_three
handle_four endp
handle_three proc
	mov		r8, [rcx].SPOOFER.Arg03
	jmp		handle_two
handle_three endp
handle_two proc
	mov		rdx, [rcx].SPOOFER.Arg02
	jmp		handle_one
handle_two endp
handle_one proc
	mov		rcx, [rcx].SPOOFER.Arg01
	jmp		handle_none
handle_one endp

handle_none proc
	jmp		execute
handle_none endp

execute proc
	jmp     qword ptr rax
execute endp


end