configure_file(
  input: 'pwaccessd.service.in',
  output: 'pwaccessd.service',
  configuration: {
    'LIBEXECDIR': libexecdir,
  },
  install: true,
  install_dir: systemunitdir,
)
install_data('pwaccessd.socket', install_dir : systemunitdir)

configure_file(
  input: 'pwupdd@.service.in',
  output: 'pwupdd@.service',
  configuration: {
    'LIBEXECDIR': libexecdir,
  },
  install: true,
  install_dir: systemunitdir,
)
install_data('pwupdd.socket', install_dir : systemunitdir)

configure_file(
  input: 'newidmapd.service.in',
  output: 'newidmapd.service',
  configuration: {
    'LIBEXECDIR': libexecdir,
  },
  install: true,
  install_dir: systemunitdir,
)
install_data('newidmapd.socket', install_dir : systemunitdir)

