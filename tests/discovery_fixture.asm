; Synthetic, non-executable test input for discovery. No client image bytes.
; Fixed assembly contract: do not generate this file from production rules at build time.
; Changes to discovery rules must be checked against this independent fixture.
.686
.model flat
option casemap:none
ASSUME fs:NOTHING
EXTERN __imp__GlobalMemoryStatus@4:DWORD
EXTERN __imp__HeapAlloc@12:DWORD
.data
ALIGN 16
pool_globals DWORD 020000000h,02bffff70h
 DWORD 02c000000h,02c9fff70h
 DWORD 02ca01000h,02da00f70h
 DWORD 02ca00000h,02ca00f70h
 DWORD 02da01000h,02da01f70h
 DWORD 0,0
heap_handle DWORD 0
vtable DWORD 0
dispatch_table DWORD OFFSET stub, OFFSET resource_route, 5 DUP(OFFSET stub)
DB 400h DUP(0)
.code

initializer:
    sub esp, 020h
    push esi
    push edi
    mov esi, ecx
    mov ecx, 8
    xor eax, eax
    lea edi, [esp + 8]
    rep stosd
    lea eax, [esp + 8]
    mov dword ptr [esp + 8], 020h
    push eax
    call dword ptr [__imp__GlobalMemoryStatus@4]
    initializer_query_return: mov eax, dword ptr [esp + 010h]
    mov ecx, 05a02000h
    shr eax, 014h
    cmp eax, 080h
    mov dword ptr [esi + 4], eax
    mov edi, 04000000h
    jle initializer_allocate
    initializer_cap_compare: cmp eax, 256
    jle initializer_calculate
    initializer_cap_store: mov dword ptr [esi + 4], 256
    initializer_calculate: mov eax, dword ptr [esi + 4]
    sub eax, 080h
    shl eax, 014h
    lea edi, [eax + 04000000h]
    lea ecx, [eax + 05a02000h]
    initializer_allocate: push ecx
    call backing
    add esp, 4
    mov dword ptr [esi + 0ch], eax
    test eax, eax
    jne initializer_retry_result
    push 05a02000h
    mov edi, 04000000h
    call backing
    add esp, 4
    mov dword ptr [esi + 0ch], eax
    initializer_retry_result: mov eax, dword ptr [esi + 0ch]
    test eax, eax
    jne initializer_align
    pop edi
    xor al, al
    pop esi
    add esp, 020h
    ret
    initializer_align: add eax, 0fh
    push ebx
    and al, 0f0h
    push ebp
    mov dword ptr [esi + 8], eax
    lea esi, [eax + edi]
    add edi, -080h
    push edi
    push eax
    lea ebx, [esi + 0a00000h]
    lea ebp, [ebx + 01000h]
    call pool0
    push 09fff80h
    push esi
    call pool1
    push 0f80h
    push ebx
    call pool3
    push 0ffff80h
    push ebp
    call pool2
    add ebp, 01000000h
    push 0f80h
    push ebp
    call pool4
    add esp, 028h
    mov al, 1
    pop ebp
    pop ebx
    pop edi
    pop esi
    add esp, 020h
    ret

pool0:
    mov eax, dword ptr [esp + 8]
    mov ecx, dword ptr [esp + 4]
    push OFFSET pool_globals + 4
    push OFFSET pool_globals + 0
    push eax
    push ecx
    call builder
    add esp, 010h
    ret

pool1:
    mov eax, dword ptr [esp + 8]
    mov ecx, dword ptr [esp + 4]
    push OFFSET pool_globals + 12
    push OFFSET pool_globals + 8
    push eax
    push ecx
    call builder
    add esp, 010h
    ret

pool2:
    mov eax, dword ptr [esp + 8]
    mov ecx, dword ptr [esp + 4]
    push OFFSET pool_globals + 20
    push OFFSET pool_globals + 16
    push eax
    push ecx
    call builder
    add esp, 010h
    ret

pool3:
    mov eax, dword ptr [esp + 8]
    mov ecx, dword ptr [esp + 4]
    push OFFSET pool_globals + 28
    push OFFSET pool_globals + 24
    push eax
    push ecx
    call builder
    add esp, 010h
    ret

pool4:
    mov eax, dword ptr [esp + 8]
    mov ecx, dword ptr [esp + 4]
    push OFFSET pool_globals + 36
    push OFFSET pool_globals + 32
    push eax
    push ecx
    call builder
    add esp, 010h
    ret

builder:
    mov edx, dword ptr [esp + 8]
    mov ecx, dword ptr [esp + 0ch]
    mov eax, dword ptr [esp + 4]
    and edx, 0fffffff0h
    mov dword ptr [ecx], eax
    push ebx
    lea eax, [edx + eax - 010h]
    mov edx, dword ptr [esp + 014h]
    push esi
    xor esi, esi
    mov dword ptr [edx], eax
    mov eax, dword ptr [ecx]
    push edi
    mov ebx, dword ptr [eax + 018h]
    mov dword ptr [eax + 0ch], esi
    mov edi, dword ptr [edx]
    mov dword ptr [eax + 014h], esi
    mov dword ptr [eax + 8], edi
    mov edi, dword ptr [edx]
    mov dword ptr [eax + 010h], edi
    mov edi, 0fffffffch
    and ebx, edi
    mov dword ptr [eax + 4], esi
    mov dword ptr [eax + 018h], ebx
    mov dword ptr [eax + 01ch], esi
    mov eax, dword ptr [edx]
    mov edx, dword ptr [ecx]
    mov dword ptr [eax + 0ch], edx
    mov dword ptr [eax + 8], esi
    mov ecx, dword ptr [ecx]
    mov dword ptr [eax + 010h], esi
    mov dword ptr [eax + 014h], ecx
    mov ecx, dword ptr [eax + 018h]
    and ecx, edi
    mov dword ptr [eax + 01ch], esi
    pop edi
    pop esi
    mov dword ptr [eax + 4], 1
    mov dword ptr [eax + 018h], ecx
    pop ebx
    ret

reverse_allocator:
    mov eax, dword ptr [esp + 4]
    mov edx, dword ptr [pool_globals + 40]
    add eax, edx
    push esi
    push edi
    mov dword ptr [pool_globals + 40], 0
    lea edi, [eax + 0fh]
    and edi, 0fffffff0h
    cmp edi, 020h
    jae reverse_allocator_begin
    mov edi, 020h
    reverse_allocator_begin: mov esi, dword ptr [esp + 014h]
    reverse_allocator_walk: mov eax, dword ptr [esi + 0ch]
    test eax, eax
    je reverse_allocator_failure
    mov esi, dword ptr [esi + 014h]
    mov eax, dword ptr [esi + 4]
    test eax, eax
    jne reverse_allocator_walk
    mov ecx, esi
    call size_helper
    lea ecx, [edi + 020h]
    cmp eax, ecx
    jl reverse_allocator_walk
    mov ecx, dword ptr [esi + 8]
    mov edx, dword ptr [pool_globals + 44]
    mov eax, ecx
    sub eax, edi
    sub eax, 020h
    cmp eax, esi
    mov dword ptr [eax + 01ch], edx
    je reverse_allocator_whole
    mov dword ptr [eax + 8], ecx
    mov dword ptr [eax + 0ch], esi
    mov dword ptr [ecx + 0ch], eax
    mov dword ptr [esi + 8], eax
    mov esi, eax
    pop edi
    mov eax, dword ptr [esi + 018h]
    mov dword ptr [esi + 4], 1
    and al, 0fch
    mov dword ptr [esi + 018h], eax
    mov eax, esi
    pop esi
    ret
    reverse_allocator_failure: pop edi
    xor eax, eax
    pop esi
    ret
    reverse_allocator_whole: mov eax, dword ptr [esi + 014h]
    test eax, eax
    je reverse_allocator_mark
    mov ecx, dword ptr [esi + 010h]
    mov dword ptr [eax + 010h], ecx
    mov edx, dword ptr [esi + 010h]
    mov eax, dword ptr [esi + 014h]
    mov dword ptr [edx + 014h], eax
    reverse_allocator_mark: mov eax, dword ptr [esi + 018h]
    mov dword ptr [esi + 4], 1
    and al, 0fch
    pop edi
    mov dword ptr [esi + 018h], eax
    mov eax, esi
    pop esi
    ret

size_helper:
    mov eax, dword ptr [ecx + 8]
    test eax, eax
    je size_helper_empty
    sub eax, ecx
    sub eax, 020h
    ret
    size_helper_empty: xor eax, eax
    ret

resource_route:
    mov ecx, dword ptr [pool_globals + 4]
    mov edx, dword ptr [pool_globals]
    push 0
    push ecx
    push edx
    push 020h
    call reverse_allocator
    add esp, 010h
    test eax, eax
    je stub
    mov dword ptr [eax], OFFSET vtable
    add eax, 020h
    ret

backing:
    push 1
    push dword ptr [esp + 8]
    call backing_retry
    pop ecx
    pop ecx
    ret

backing_retry:
    cmp dword ptr [esp + 4], -020h
    ja backing_retry_failure
    backing_retry_again: push dword ptr [esp + 4]
    call heap_adapter
    test eax, eax
    pop ecx
    jne backing_retry_done
    cmp dword ptr [esp + 8], eax
    je backing_retry_done
    push dword ptr [esp + 4]
    call stub
    test eax, eax
    pop ecx
    jne backing_retry_again
    backing_retry_failure: xor eax, eax
    backing_retry_done: ret

resource_dispatcher:
    mov eax, dword ptr [esp + 4]
    mov edx, dword ptr [pool_globals + 40]
    add edx, eax
    mov eax, dword ptr [esp + 8]
    cmp eax, 6
    mov dword ptr [pool_globals + 40], edx
    ja stub
    jmp dword ptr [eax*4 + dispatch_table]

heap_adapter:
    push ebp
    mov ebp, esp
    push -1
    push 0
    push dword ptr [heap_handle]
    call dword ptr [__imp__HeapAlloc@12]
    mov ecx, dword ptr [ebp - 10h]
    mov dword ptr fs:[0], ecx
    pop edi
    pop esi
    pop ebx
    leave
    ret
stub:
    ret
; Unused executable room for bounded relocation/ambiguity mutations.
DB 11000h DUP(090h)
END
