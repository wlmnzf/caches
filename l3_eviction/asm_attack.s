.global asm_attack

asm_attack:
  // Set list
  mov %rax, %r9
  // Set size
  mov %rbx, %r10
  // Candidate
  mov %rcx, %r11
  
  mfence
  lfence
  rdtsc
  mov %eax, %edi
  // Access candidate cache line
  mov (%r11), %rax
  mfence
  lfence
  rdtsc
  sub %edi, %eax
  mov %r9, %rcx
  lea (%rip), %rdx
  ret
