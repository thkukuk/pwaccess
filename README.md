# pwaccess

The pwaccess package contains a library and a systemd socket activated service, which allows tools to read `/etc/shadow` entries without the need of having setuid/setgid bits set or to allow tools to authenticate users with a password (same interface and behavior as `unix_chkpwd` from Linux-PAM). The communication is done via varlink.

## pam_unix_ng.so

The `pam_unix_ng.so` PAM module uses `pwaccessd` as backend for authentication and to check if the account is expired. 
Changing the password is only possible if run as root, no varlink call for this. Use `passwd` from this package instead.
If `pwaccessd` is not running, it tries authentication and account expiration itself as fallback.
