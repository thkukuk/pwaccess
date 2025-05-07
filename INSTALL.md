# Building and installing pwaccess

## Building with Meson

pwaccess requires a relatively recent version of Meson.

Building with Meson is quite simple:

```shell
$ meson setup build
$ meson compile -C build
$ meson test -C build
$ sudo meson install -C build
```

If you want to build with the address sanitizer enabled, add
`-Db_sanitize=address` as an argument to `meson setup`.
