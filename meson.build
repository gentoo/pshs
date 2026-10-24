project('pshs', 'cpp',
        version: '0.4.4',
        license: 'GPL-2.0-or-later')

cxx = meson.get_compiler('cpp')

libevent = dependency('libevent')
magic = dependency('libmagic', required: get_option('libmagic'))
qrencode = dependency('libqrencode', required: get_option('qrencode'))
upnp = dependency('miniupnpc', required: get_option('upnp'))

crypto = dependency('libcrypto', required: get_option('ssl'))
ssl = dependency('libssl',
                 version: '>=1.1',
                 required: get_option('ssl'))
libevent_ssl = dependency('libevent_openssl',
                          version: '>=2.1',
                          required: get_option('ssl'))

conf_data = configuration_data()
conf_data.set('PACKAGE_NAME', '"' + meson.project_name() + '"')
conf_data.set('PACKAGE_VERSION', '"' + meson.project_version() + '"')
conf_data.set('PACKAGE_STRING', 'PACKAGE_NAME "-" PACKAGE_VERSION')

conf_data.set('HAVE_NL_LANGINFO',
              cxx.has_function('nl_langinfo',
                               prefix: '#include <langinfo.h>'))
conf_data.set('HAVE_GETIFADDRS',
              cxx.has_function('getifaddrs',
                               prefix: '#include <ifaddrs.h>'))

conf_data.set('HAVE_LIBMAGIC', magic.found())
conf_data.set('HAVE_LIBMINIUPNPC', upnp.found())
conf_data.set('HAVE_LIBSSL',
              crypto.found() and ssl.found() and libevent_ssl.found())
conf_data.set('HAVE_LIBQRENCODE', qrencode.found())

configure_file(output: 'config.h', configuration: conf_data)

executable('pshs',
  [
    'src/main.cxx',
    'src/content-type.cxx',
    'src/index.cxx',
    'src/handlers.cxx',
    'src/network.cxx',
    'src/rtnl.cxx',
    'src/qrencode.cxx',
    'src/ssl.cxx',
  ],
  dependencies: [libevent, magic, qrencode, upnp, crypto, ssl, libevent_ssl],
  install: true)
