# pwaccess

The pwaccess package contains a library and a systemd socket activated service, which allows tools to read `/etc/shadow` entries without the need of having setuid/setgid bits set or to allow tools to authenticate users with a password (same interface and behavior as `unix_chkpwd` from Linux-PAM). The communication is done via varlink.
