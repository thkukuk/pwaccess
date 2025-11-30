executable('dump-privs', 'dump-privs.c',
           include_directories : inc,
           dependencies : [libselinux],
           install : get_option('tools'))
executable('scan-caps', 'scan-caps.c',
           include_directories : inc,
           dependencies : [libcap],
           install : get_option('tools'))

