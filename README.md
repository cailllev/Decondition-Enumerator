# Decondition Enumerator
see https://blog.levi.wiki/post/2025-12-05-decondition-everything

TL;DR: MDE has some "behaviour tracking" thresholds, allowing interesting deconditioning attacks:

## LSASS Direct Deconditioning
with LSASS dumping as an example
* direct: open lsass and call MiniDumpWriteDump --> block
* decondition: open any non-critical process and call MiniDumpWriteDump (20x), then open lsass and call MiniDumpWriteDump --> ok

## LSASS Indirect Deconditioning
with LSASS dumping as an example
* `A.exe`.exe opens lsass and calls MiniDumpWriteDump --> block
* `A'.exe`, deconditions (20x), then opens lsass and calls MiniDumpWriteDump --> ok
* `A.exe` opens lsass and calls MiniDumpWriteDump --> ok
`A'.exe` deconditioned lsass dumping for all exes similar to  `A'.exe`, or even ALL exes (TODO verify)

## Mem Alloc and RemoteThread Execute
with SirAllocALot, see https://github.com/dobin/SuperMega
* `for _ in 1000: VirtualAlloc, VirtualProtect, VirtualFree`
* TODO: verify again after 2 years?

# Related Techniques
## Behaviour Bypass tourgh Silo-Binding 
see https://insomnihack.ch/talks/silo-binding-uncovering-the-ghost-in-the-silo/
* `Invoke-Mimikatz` from `powershell.exe` -> detected by AMSI (as expected)
* `Invoke-Mimikatz` from `powershell.exe`, but PS binded to `TiWorker.exe` -> ignored by AMSI, works (unexpected)
* TODO: verify with https://github.com/bitdefender/bindutil-toolset/
