@echo off

set common_compiler_flags= -O2 -nologo -fp:fast -fp:except- -Zc:threadSafeInit- -EHa- -Gm- -GR- -GS- -Gs9999999 -WX -W4 -wd4201 -wd4189 -wd4100 -wd4505 -Gd -Oi -FC -D_CRT_SECURE_NO_WARNINGS
set common_linker_flags= -STACK:0x100000,0x100000 -nodefaultlib -incremental:no -subsystem:console,5.2 -opt:ref user32.lib kernel32.lib ntdll.lib vcruntime.lib

if not exist run_tree mkdir run_tree
pushd run_tree
cl %common_compiler_flags% ..\src\sot_updater.cpp ..\src\msvc.c /link %common_linker_flags%
popd
