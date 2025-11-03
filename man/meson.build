xsltproc_exe = find_program('xsltproc', required : get_option('man'))
want_man = (get_option('man').enabled() or get_option('man').auto()) and xsltproc_exe.found()
xsltproc_flags = [
        '--nonet',
        '--xinclude',
        '--stringparam', 'version', '@0@'.format(meson.project_version()),
        '--path',
        '@0@:@1@'.format(meson.current_build_dir(), meson.current_source_dir())]

custom_man_xsl = files('custom-man.xsl')

xslt_cmd = [xsltproc_exe, '-o', '@OUTPUT0@'] + xsltproc_flags

mandir1 = get_option('mandir') / 'man1'
mandir8 = get_option('mandir') / 'man8'

if xsltproc_exe.found()
custom_target('chage.1',
              input : 'chage.1.xml',
              output : 'chage.1',
              command : xslt_cmd + [custom_man_xsl, '@INPUT@'],
              install : want_man,
              install_dir : mandir1)
custom_target('chsh.1',
              input : 'chsh.1.xml',
              output : 'chsh.1',
              command : xslt_cmd + [custom_man_xsl, '@INPUT@'],
              install : want_man,
              install_dir : mandir1)
custom_target('expiry.1',
              input : 'expiry.1.xml',
              output : 'expiry.1',
              command : xslt_cmd + [custom_man_xsl, '@INPUT@'],
              install : want_man,
              install_dir : mandir1)
custom_target('pam_unix_ng.8',
              input : 'pam_unix_ng.8.xml',
              output : 'pam_unix_ng.8',
              command : xslt_cmd + [custom_man_xsl, '@INPUT@'],
              install : want_man,
              install_dir : mandir8)
custom_target('pam_debuginfo.8',
              input : 'pam_debuginfo.8.xml',
              output : 'pam_debuginfo.8',
              command : xslt_cmd + [custom_man_xsl, '@INPUT@'],
              install : want_man,
              install_dir : mandir8)
endif
