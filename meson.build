project(
  'account-utils',
  'c',
  meson_version : '>= 0.61.0',
  default_options : [
                  'prefix=/usr',
                  'sysconfdir=/etc',
                  'localstatedir=/var',
                  'buildtype=debugoptimized',
  		  'default_library=shared',
		  'b_pie=true',
                  'b_lto=true',
		  'warning_level=2'],
  license : ['GPL-2.0-or-later', 'LGPL-2.1-or-later'],
  version : '0.4.0',
)

distribution = get_option('distribution')
if distribution == ''
  distribution = 'example'
endif

conf = configuration_data()
conf.set_quoted('VERSION', meson.project_version())
conf.set_quoted('PACKAGE', meson.project_name())
conf.set_quoted('_VARLINK_PWACCESS_SOCKET_DIR', '/run/account')
conf.set_quoted('_VARLINK_PWACCESS_SOCKET', '/run/account/pwaccess-socket')
conf.set_quoted('_VARLINK_PWUPD_SOCKET_DIR', '/run/account')
conf.set_quoted('_VARLINK_PWUPD_SOCKET', '/run/account/pwupd-socket')
conf.set_quoted('_VARLINK_NEWIDMAPD_SOCKET_DIR', '/run/account')
conf.set_quoted('_VARLINK_NEWIDMAPD_SOCKET', '/run/account/newidmapd-socket')
conf.set_quoted('_PATH_VENDORDIR', get_option('vendordir'))

cc = meson.get_compiler('c')
pkg = import('pkgconfig')
inc = include_directories(['include','libcommon'])

add_project_arguments(['-D_GNU_SOURCE=1',
		       '-DXTSTRINGDEFINES',
		       '-D_FORTIFY_SOURCE=2',
                       '-D_FILE_OFFSET_BITS=64',
                       '-D_TIME_BITS=64'], language : 'c')

possible_cc_flags = [
		  '-fstack-protector-strong',
		  '-funwind-tables',
		  '-fasynchronous-unwind-tables',
		  '-fstack-clash-protection',
		  '-Werror=return-type',
		  '-Wbad-function-cast',
		  '-Wcast-align',
                  '-Wformat-security',
		  '-Winline',
		  '-Wmissing-declarations',
		  '-Wmissing-prototypes',
		  '-Wnested-externs',
		  '-Wshadow',
		  '-Wstrict-prototypes',
		  '-Wundef',
		  ]
add_project_arguments(cc.get_supported_arguments(possible_cc_flags), language : 'c')

prefixdir = get_option('prefix')
if not prefixdir.startswith('/')
        error('Prefix is not absolute: "@0@"'.format(prefixdir))
endif
libexecdir = join_paths(prefixdir, get_option('libexecdir'))
systemunitdir = prefixdir / 'lib/systemd/system'
tmpfilesdir = prefixdir / 'lib/tmpfiles.d'
pamlibdir = get_option('pamlibdir')
if pamlibdir == ''
        pamlibdir = get_option('libdir') / 'security'
endif
pamconfdir = get_option('pamconfdir')
if pamconfdir == ''
        pamconfdir = prefixdir / 'lib/pam.d'
endif

libpam = dependency('pam', required: true)
libpam_misc = dependency('pam_misc', required: true)
libsystemd = dependency('libsystemd', version: '>= 257', required: true)
libcrypt = dependency('libxcrypt', version: '>= 4.4.27', required: true)
libeconf = dependency('libeconf', version : '>=0.7.5', required : true)
libcap = dependency('libcap', required: get_option('tools'))
libselinux = dependency('libselinux', required: get_option('selinux'))
if libselinux.found()
  conf.set('WITH_SELINUX', 1)
endif

libpwaccess_c = files('lib/varlink.c')
libpwaccess_map = 'lib/libpwaccess.map'
libpwaccess_map_version = '-Wl,--version-script,@0@/@1@'.format(meson.current_source_dir(), libpwaccess_map)

libpwaccess = shared_library(
  'pwaccess',
  libpwaccess_c,
  include_directories : inc,
  link_args : ['-shared',
               libpwaccess_map_version],
  link_depends : libpwaccess_map,
  dependencies : [libsystemd],
  install : true,
  version : meson.project_version(),
  soversion : '0'
)
install_headers('include/pwaccess.h')

pkg.generate(
  libpwaccess,
  name : 'libpwaccess',
  description : 'library to read passwd and shadow entries via varlink daemon',
  version : meson.project_version(),
)

libcommon_c = files('libcommon/chauthtok.c',
                    'libcommon/check_caller_perms.c',
                    'libcommon/chfn_checks.c',
                    'libcommon/create_hash.c',
                    'libcommon/drop_privs.c',
                    'libcommon/files.c',
                    'libcommon/get_logindefs.c',
                    'libcommon/mkdir_p.c',
                    'libcommon/no_new_privs.c',
                    'libcommon/string-util-fundamental.c',
                    'libcommon/varlink-client-common.c',
                    'libcommon/verify.c')

libcommon = static_library(
  'common',
  libcommon_c,
  include_directories : inc,
  install : false
)

pwaccessd_c = ['src/pwaccessd.c', 'src/varlink-org.openSUSE.pwaccess.c',
	       'src/varlink-service-common.c']
pwupdd_c = ['src/pwupdd.c', 'src/varlink-org.openSUSE.pwupd.c',
            'src/varlink-service-common.c']
newidmapd_c = ['src/newidmapd.c', 'src/varlink-org.openSUSE.newidmapd.c',
               'libcommon/mkdir_p.c',
               'src/varlink-service-common.c']

executable('pwaccessd',
           pwaccessd_c,
           include_directories : inc,
	   link_with : [libcommon],
           dependencies : [libsystemd, libcrypt],
           install_dir : libexecdir,
           install : true)

executable('pwupdd',
           pwupdd_c,
           include_directories : inc,
	   link_with : [libcommon, libpwaccess],
	   dependencies : [libpam, libsystemd, libeconf, libselinux],
           install_dir : libexecdir,
           install : true)

executable('newidmapd',
           newidmapd_c,
           include_directories : inc,
           link_with : [libpwaccess],
           dependencies : [libsystemd, libeconf],
           install_dir : libexecdir,
           install : true)

executable('newuidmap', 'src/newxidmap.c',
           c_args : '-DXID="uid"',
           include_directories : inc,
           link_with : [libcommon],
           dependencies : [libsystemd],
           install : true)
executable('newgidmap', 'src/newxidmap.c',
           c_args : '-DXID="gid"',
           include_directories : inc,
           link_with : [libcommon],
           dependencies : [libsystemd],
           install : true)

executable('chage', 'src/chage.c', 'src/get_value.c',
           include_directories : inc,
           link_with : [libcommon, libpwaccess],
           dependencies : [libsystemd, libpam, libpam_misc, libeconf],
           install : true)
executable('chfn', 'src/chfn.c', 'src/get_value.c',
           include_directories : inc,
           link_with : [libcommon, libpwaccess],
           dependencies : [libsystemd, libpam, libpam_misc, libeconf],
           install : true)
executable('chsh', 'src/chsh.c', 'src/get_value.c',
           include_directories : inc,
           link_with : [libcommon, libpwaccess],
           dependencies : [libsystemd, libpam, libpam_misc, libeconf],
           install : true)
executable('passwd', 'src/passwd.c',
           include_directories : inc,
           link_with : [libcommon, libpwaccess],
           dependencies : [libsystemd, libpam, libpam_misc, libeconf],
           install : true)
executable('expiry', 'src/expiry.c',
           include_directories : inc,
           link_with : [libpwaccess, libcommon],
           dependencies : [libsystemd, libpam, libpam_misc],
           install : true)

pam_unix_ng_c = files('src/pam_unix_ng-common.c', 'src/pam_unix_ng-session.c',
                      'src/pam_unix_ng-acct.c', 'src/pam_unix_ng-auth.c',
                      'src/pam_unix_ng-passwd.c')
pam_unix_ng_map = 'src/pam_unix_ng.map'
pam_unix_ng_map_version = '-Wl,--version-script,@0@/@1@'.format(meson.current_source_dir(), pam_unix_ng_map)

pam_unix_ng = shared_library(
  'pam_unix_ng',
  pam_unix_ng_c,
  name_prefix : '',
  include_directories : inc,
  link_args : ['-shared', pam_unix_ng_map_version],
  link_depends : pam_unix_ng_map,
  link_with : [libpwaccess, libcommon],
  dependencies : [libcrypt, libeconf, libpam, libselinux],
  install : true,
  install_dir : pamlibdir
)

pam_debuginfo_c = ['src/pam_debuginfo.c', 'libcommon/no_new_privs.c',
                   'libcommon/string-util-fundamental.c']

pam_debuginfo = shared_library(
  'pam_debuginfo',
  pam_debuginfo_c,
  name_prefix : '',
  include_directories : inc,
  link_args : ['-shared', pam_unix_ng_map_version],
  link_depends : pam_unix_ng_map,
  dependencies : [libpam, libselinux],
  install : true,
  install_dir : pamlibdir
)

# create config.h
subdir('include')

# systemd units
subdir('units')

if get_option('tools')
  subdir('tools')
endif

# example pam configuration files
pamdpwupdchfnsrc = 'pam.d' / distribution / 'pwupd-chfn'
pamdpwupdchshsrc = 'pam.d' / distribution / 'pwupd-chsh'
pamdpwupdpasswdsrc = 'pam.d' / distribution / 'pwupd-passwd'
pamdpasswdsrc = 'pam.d' / distribution / 'passwd'
install_data(pamdpwupdchfnsrc, install_dir : pamconfdir)
install_data(pamdpwupdchshsrc, install_dir : pamconfdir)
install_data(pamdpwupdpasswdsrc, install_dir : pamconfdir)
install_data(pamdpasswdsrc, install_dir : pamconfdir)

# Unit tests
subdir('tests')

# Manual pages
subdir('man')

subdir('example')
