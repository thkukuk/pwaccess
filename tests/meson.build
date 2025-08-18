# This file builds and runs the unit tests

libdl = cc.find_library('dl')

tst_dlopen_exe = executable('tst-dlopen', 'tst-dlopen.c', dependencies : libdl,
                        include_directories : inc)
test('tst-dlopen', tst_dlopen_exe, args : ['pam_unix-ng.so'])
