# pwaccess

The pwaccess package contains the utilities and services to do user management and authentication without the need for setuid/setgid bits. This allows the stack to work with `NoNewPrivs` enabled (means setuid/setgid binaries will no longer work). Communication happens via [varlink](https://varlink.org).

There are two services:
* `pwaccessd` is a systemd socket activated service which provides account information in `passwd` and `shadow` format, checks if the password or account is expired and verifies the password. Normal users have only access to their own passwd and shadow entry, root has access to all accounts.
* `pwupdd` is a inetd style socket activated service, which means for every request a own instance is started. It provides methods to change the password, shell and the GECOS field. An user is allowed to modify it's own data after authentication via PAM, root can additional update all passwd and shadow entries via an own method.

There are PAM modules:
* `pam_unix_ng.so` is a UNIX style PAM module like `pam_unix.so`, except that it uses `pwaccessd` to get access to the account information and do the authentication. If `pwaccessd` is not running, it falls back to traditional, local authentication. For this it needs to run as root. Changing the password is always done local, but there is a `passwd` command which uses `pwupdd` with a PAM stack for this.
* `pam_debuginfo.so` is a simple PAM module for debugging purpose, it prints all available relevant information like PAM flags, PAM data, euid, uid, no_new_privs state, etc.
  
There are additional utilities, which don't use the standard glibc functions to modify passwd and shadow, but `pwaccessd` and `pwupdd`:
* chfn
* chsh
* expiry
* passwd

## pam_unix_ng.so

The `pam_unix_ng.so` PAM module uses `pwaccessd` as backend for authentication and to check if the account is expired. 
Changing the password is only possible if run as root, no varlink call for this. Use `passwd` from this package instead.
If `pwaccessd` is not running, it tries authentication and account expiration itself as fallback.
