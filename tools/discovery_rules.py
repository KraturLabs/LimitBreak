"""Bounded x86 semantic rules for the two observed resource-memory families.

These are instruction/operand relationships, not file hashes or client RVAs.
Labels bind decoded branch targets; $names bind discovered operands. This is
deliberately not a general x86 emulator or an arbitrary compiler recognizer.
"""

INITIALIZER = '''
sub esp, 0x20
push esi
push edi
mov esi, ecx
mov ecx, 8
xor eax, eax
lea edi, [esp + 8]
rep stosd dword ptr es:[edi], eax
lea eax, [esp + 8]
mov dword ptr [esp + 8], 0x20
push eax
call dword ptr [$memory_iat]
query_return: mov eax, dword ptr [esp + 0x10]
mov ecx, 0x5a02000
shr eax, 0x14
cmp eax, 0x80
mov dword ptr [esi + 4], eax
mov edi, 0x4000000
jle @allocate
cap_compare: cmp eax, $cap
jle @calculate
cap_store: mov dword ptr [esi + 4], $cap
calculate: mov eax, dword ptr [esi + 4]
sub eax, 0x80
shl eax, 0x14
lea edi, [eax + 0x4000000]
lea ecx, [eax + 0x5a02000]
allocate: push ecx
call $backing
add esp, 4
mov dword ptr [esi + 0xc], eax
test eax, eax
jne @retry_result
push 0x5a02000
mov edi, 0x4000000
call $backing
add esp, 4
mov dword ptr [esi + 0xc], eax
retry_result: mov eax, dword ptr [esi + 0xc]
test eax, eax
jne @align
pop edi
xor al, al
pop esi
add esp, 0x20
ret
align: add eax, 0xf
push ebx
and al, 0xf0
push ebp
mov dword ptr [esi + 8], eax
lea esi, [eax + edi]
add edi, -0x80
push edi
push eax
lea ebx, [esi + 0xa00000]
lea ebp, [ebx + 0x1000]
call $pool0
push 0x9fff80
push esi
call $pool1
push 0xf80
push ebx
call $pool3
push 0xffff80
push ebp
call $pool2
add ebp, 0x1000000
push 0xf80
push ebp
call $pool4
add esp, 0x28
mov al, 1
pop ebp
pop ebx
pop edi
pop esi
add esp, 0x20
ret
'''

POOL_WRAPPER = '''
mov eax, dword ptr [esp + 8]
mov ecx, dword ptr [esp + 4]
push $end
push $head
push eax
push ecx
call $builder
add esp, 0x10
ret
'''

BUILDER = '''
mov edx, dword ptr [esp + 8]
mov ecx, dword ptr [esp + 0xc]
mov eax, dword ptr [esp + 4]
and edx, 0xfffffff0
mov dword ptr [ecx], eax
push ebx
lea eax, [edx + eax - 0x10]
mov edx, dword ptr [esp + 0x14]
push esi
xor esi, esi
mov dword ptr [edx], eax
mov eax, dword ptr [ecx]
push edi
mov ebx, dword ptr [eax + 0x18]
mov dword ptr [eax + 0xc], esi
mov edi, dword ptr [edx]
mov dword ptr [eax + 0x14], esi
mov dword ptr [eax + 8], edi
mov edi, dword ptr [edx]
mov dword ptr [eax + 0x10], edi
mov edi, 0xfffffffc
and ebx, edi
mov dword ptr [eax + 4], esi
mov dword ptr [eax + 0x18], ebx
mov dword ptr [eax + 0x1c], esi
mov eax, dword ptr [edx]
mov edx, dword ptr [ecx]
mov dword ptr [eax + 0xc], edx
mov dword ptr [eax + 8], esi
mov ecx, dword ptr [ecx]
mov dword ptr [eax + 0x10], esi
mov dword ptr [eax + 0x14], ecx
mov ecx, dword ptr [eax + 0x18]
and ecx, edi
mov dword ptr [eax + 0x1c], esi
pop edi
pop esi
mov dword ptr [eax + 4], 1
mov dword ptr [eax + 0x18], ecx
pop ebx
ret
'''

REVERSE = '''
mov eax, dword ptr [esp + 4]
mov edx, dword ptr [$request]
add eax, edx
push esi
push edi
mov dword ptr [$request], 0
lea edi, [eax + 0xf]
and edi, 0xfffffff0
cmp edi, 0x20
jae @begin
mov edi, 0x20
begin: mov esi, dword ptr [esp + 0x14]
walk: mov eax, dword ptr [esi + 0xc]
test eax, eax
je @failure
mov esi, dword ptr [esi + 0x14]
mov eax, dword ptr [esi + 4]
test eax, eax
jne @walk
mov ecx, esi
call $size_helper
lea ecx, [edi + 0x20]
cmp eax, ecx
jl @walk
mov ecx, dword ptr [esi + 8]
mov edx, dword ptr [$tag]
mov eax, ecx
sub eax, edi
sub eax, 0x20
cmp eax, esi
mov dword ptr [eax + 0x1c], edx
je @whole
mov dword ptr [eax + 8], ecx
mov dword ptr [eax + 0xc], esi
mov dword ptr [ecx + 0xc], eax
mov dword ptr [esi + 8], eax
mov esi, eax
pop edi
mov eax, dword ptr [esi + 0x18]
mov dword ptr [esi + 4], 1
and al, 0xfc
mov dword ptr [esi + 0x18], eax
mov eax, esi
pop esi
ret
failure: pop edi
xor eax, eax
pop esi
ret
whole: mov eax, dword ptr [esi + 0x14]
test eax, eax
je @mark
mov ecx, dword ptr [esi + 0x10]
mov dword ptr [eax + 0x10], ecx
mov edx, dword ptr [esi + 0x10]
mov eax, dword ptr [esi + 0x14]
mov dword ptr [edx + 0x14], eax
mark: mov eax, dword ptr [esi + 0x18]
mov dword ptr [esi + 4], 1
and al, 0xfc
pop edi
mov dword ptr [esi + 0x18], eax
mov eax, esi
pop esi
ret
'''

SIZE_HELPER = '''
mov eax, dword ptr [ecx + 8]
test eax, eax
je @empty
sub eax, ecx
sub eax, 0x20
ret
empty: xor eax, eax
ret
'''

RESOURCE_ROUTE = '''
mov ecx, dword ptr [$end]
mov edx, dword ptr [$head]
push 0
push ecx
push edx
push 0x20
call $reverse
add esp, 0x10
test eax, eax
je $route_failure
mov dword ptr [eax], $vtable
add eax, 0x20
ret
'''

BACKING = '''
push 1
push dword ptr [esp + 8]
call $retry
pop ecx
pop ecx
ret
'''

RETRY = '''
cmp dword ptr [esp + 4], -0x20
ja @failure
again: push dword ptr [esp + 4]
call $heap_adapter
test eax, eax
pop ecx
jne @done
cmp dword ptr [esp + 8], eax
je @done
push dword ptr [esp + 4]
call $new_handler
test eax, eax
pop ecx
jne @again
failure: xor eax, eax
done: ret
'''

DISPATCH = '''
mov eax, dword ptr [esp + 4]
mov edx, dword ptr [$request]
add edx, eax
mov eax, dword ptr [esp + 8]
cmp eax, 6
mov dword ptr [$request], edx
ja $default
jmp dword ptr [eax*4 + $table]
'''

ADAPTER_PREFIX = 'push ebp\nmov ebp, esp\npush -1'

HEAP_TAIL = '''
push 0
push dword ptr [$heap_handle]
call dword ptr [$heap_iat]
mov ecx, dword ptr [ebp - 0x10]
mov dword ptr fs:[0], ecx
pop edi
pop esi
pop ebx
leave
ret
'''
