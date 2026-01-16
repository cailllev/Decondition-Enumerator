# Decondition Enumerator
see https://blog.levi.wiki/post/2025-12-05-decondition-everything

TL;DR: MDE has some "behaviour tracking" thresholds, allowing interesting deconditioning attacks:

## Direct Deconditioning
with LSASS dumping as an example
* direct: open lsass and call MiniDumpWriteDump --> block
* decondition: open any non-critical process and call MiniDumpWriteDump (20x), then open lsass and call MiniDumpWriteDump --> ok

## Indirect Deconditioning
with LSASS dumping as an example
* `A.exe`.exe opens lsass and calls MiniDumpWriteDump --> block
* `A'.exe`, deconditions (20x), then opens lsass and calls MiniDumpWriteDump --> ok
* `A.exe` opens lsass and calls MiniDumpWriteDump --> ok
`A'.exe` deconditioned lsass dumping for all exes similar to  `A'.exe`, or even ALL exes (TODO verify)
