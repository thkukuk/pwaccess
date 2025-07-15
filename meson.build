project(
  'pwaccess',
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
  version : '0.2.0',
)

conf = configuration_data()
conf.set_quoted('VERSION', meson.project_version())
conf.set_quoted('PACKAGE', meson.project_name())
conf.set_quoted('_VARLINK_PWACCESS_SOCKET_DIR', '/run/pwaccess')
conf.set_quoted('_VARLINK_PWACCESS_SOCKET', '/run/pwaccess/socket') 

cc = meson.get_compiler('c')
pkg = import('pkgconfig')
inc = include_directories(['include'])

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
		  '-Wcast-qual',
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

libsystemd = dependency('libsystemd', version: '>= 257', required: true)
libcrypt = dependency('libcrypt', 'libxcrypt', required: true)

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

pwaccessd_c = ['src/pwaccessd.c', 'src/varlink-org.openSUSE.pwaccess.c', 'src/mkdir_p.c', 'src/verify.c']

executable('pwaccessd',
           pwaccessd_c,
           include_directories : inc,
           dependencies : [libsystemd, libcrypt],
           install_dir : libexecdir,
           install : true)

subdir('units')

# Unit tests
#subdir('tests')

# Manual pages
#subdir('man')

subdir('example')

config_h = configure_file(
  output : 'config.h',
  configuration : conf)
