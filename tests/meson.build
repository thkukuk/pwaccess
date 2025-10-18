# This file builds and runs the unit tests

testdir = join_paths(meson.project_source_root(), 'tests/')
test_args = ['-DTESTSDIR="' + testdir + '"']

srcdir = include_directories('../src')

libdl = cc.find_library('dl')

tst_dlopen_exe = executable('tst-dlopen', 'tst-dlopen.c', dependencies : libdl,
                        include_directories : inc)
test('tst-dlopen', tst_dlopen_exe, args : ['pam_unix_ng.so'])
test('tst-dlopen', tst_dlopen_exe, args : ['pam_debuginfo.so'])

tst_update_passwd_exe = executable('tst-update_passwd', 'tst-update_passwd.c',
                        include_directories : [inc, srcdir],
                        dependencies : [libselinux],
                        c_args: test_args)
test('tst-update_passwd', tst_update_passwd_exe)

