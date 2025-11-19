// SPDX-License-Identifier: GPL-2.0-or-later

#include "varlink-org.openSUSE.pwupd.h"

static SD_VARLINK_DEFINE_STRUCT_TYPE(PasswdEntry,
				     SD_VARLINK_FIELD_COMMENT("User's login name"),
				     SD_VARLINK_DEFINE_FIELD(name,       SD_VARLINK_STRING, 0),
				     SD_VARLINK_DEFINE_FIELD(passwd,     SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
				     SD_VARLINK_DEFINE_FIELD(UID,        SD_VARLINK_INT,    0),
				     SD_VARLINK_DEFINE_FIELD(GID,        SD_VARLINK_INT,    0),
				     SD_VARLINK_DEFINE_FIELD(GECOS,      SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
				     SD_VARLINK_DEFINE_FIELD(dir,        SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
				     SD_VARLINK_DEFINE_FIELD(shell,      SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_STRUCT_TYPE(ShadowEntry,
				     SD_VARLINK_DEFINE_FIELD(name,       SD_VARLINK_STRING, 0),
				     SD_VARLINK_DEFINE_FIELD(passwd,     SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
				     SD_VARLINK_DEFINE_FIELD(lstchg,     SD_VARLINK_INT,    SD_VARLINK_NULLABLE),
				     SD_VARLINK_DEFINE_FIELD(min,        SD_VARLINK_INT,    SD_VARLINK_NULLABLE),
				     SD_VARLINK_DEFINE_FIELD(max,        SD_VARLINK_INT,    SD_VARLINK_NULLABLE),
				     SD_VARLINK_DEFINE_FIELD(warn,       SD_VARLINK_INT,    SD_VARLINK_NULLABLE),
				     SD_VARLINK_DEFINE_FIELD(inact,      SD_VARLINK_INT,    SD_VARLINK_NULLABLE),
				     SD_VARLINK_DEFINE_FIELD(expire,     SD_VARLINK_INT,    SD_VARLINK_NULLABLE),
				     SD_VARLINK_DEFINE_FIELD(flag,       SD_VARLINK_INT,    SD_VARLINK_NULLABLE));


static SD_VARLINK_DEFINE_METHOD(
                Chauthtok,
                SD_VARLINK_FIELD_COMMENT("The account of the user to change the password."),
                SD_VARLINK_DEFINE_INPUT(userName, SD_VARLINK_STRING, 0),
		SD_VARLINK_DEFINE_INPUT(flags, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                Chfn,
                SD_VARLINK_FIELD_COMMENT("The account of the user to change the GECOS information."),
                SD_VARLINK_DEFINE_INPUT(userName, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The new full name."),
                SD_VARLINK_DEFINE_INPUT(fullName, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The new room number."),
                SD_VARLINK_DEFINE_INPUT(room, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The new work phone number."),
                SD_VARLINK_DEFINE_INPUT(workPhone, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The new private phone number."),
                SD_VARLINK_DEFINE_INPUT(homePhone, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The new other field."),
                SD_VARLINK_DEFINE_INPUT(other, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                Chsh,
                SD_VARLINK_FIELD_COMMENT("The account of the user to change the shell."),
                SD_VARLINK_DEFINE_INPUT(userName, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The new shell of the user."),
                SD_VARLINK_DEFINE_INPUT(shell, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD(
		Conv,
                SD_VARLINK_FIELD_COMMENT("Response for PAM_PROMPT_ECHO_*."),
                SD_VARLINK_DEFINE_INPUT(response, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                UpdatePasswdShadow,
                SD_VARLINK_FIELD_COMMENT("Update passwd and shadow entries."),
		SD_VARLINK_FIELD_COMMENT("passwd entry"),
		SD_VARLINK_DEFINE_INPUT_BY_TYPE(passwd, PasswdEntry, SD_VARLINK_NULLABLE),
		SD_VARLINK_FIELD_COMMENT("shadow entry"),
		SD_VARLINK_DEFINE_INPUT_BY_TYPE(shadow, ShadowEntry, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
		Quit,
		SD_VARLINK_FIELD_COMMENT("Stop the daemon"),
		SD_VARLINK_DEFINE_INPUT(ExitCode, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
		SD_VARLINK_DEFINE_OUTPUT(Success, SD_VARLINK_BOOL, 0));

static SD_VARLINK_DEFINE_METHOD(
		Ping,
		SD_VARLINK_FIELD_COMMENT("Check if service is alive"),
		SD_VARLINK_DEFINE_OUTPUT(Alive, SD_VARLINK_BOOL, 0));

static SD_VARLINK_DEFINE_METHOD(
                SetLogLevel,
                SD_VARLINK_FIELD_COMMENT("The maximum log level, using BSD syslog log level integers."),
                SD_VARLINK_DEFINE_INPUT(Level, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                GetEnvironment,
                SD_VARLINK_FIELD_COMMENT("Returns the current environment block, i.e. the contents of environ[]."),
                SD_VARLINK_DEFINE_OUTPUT(Environment, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY));

static SD_VARLINK_DEFINE_ERROR(NoEntryFound);
static SD_VARLINK_DEFINE_ERROR(InvalidParameter);
static SD_VARLINK_DEFINE_ERROR(InternalError);
static SD_VARLINK_DEFINE_ERROR(AuthenticationFailed);
static SD_VARLINK_DEFINE_ERROR(InvalidShell);
static SD_VARLINK_DEFINE_ERROR(PasswordChangeAborted);
static SD_VARLINK_DEFINE_ERROR(PermissionDenied);

SD_VARLINK_DEFINE_INTERFACE(
                org_openSUSE_pwupd,
                "org.openSUSE.pwupd",
		SD_VARLINK_INTERFACE_COMMENT("PWUpdD control APIs"),
		SD_VARLINK_SYMBOL_COMMENT("Describe passwd entry"),
		&vl_type_PasswdEntry,
		SD_VARLINK_SYMBOL_COMMENT("Describe shadow entry"),
		&vl_type_ShadowEntry,
		SD_VARLINK_SYMBOL_COMMENT("Change password via PAM module"),
                &vl_method_Chauthtok,
		SD_VARLINK_SYMBOL_COMMENT("Change GECOS information of account"),
                &vl_method_Chfn,
		SD_VARLINK_SYMBOL_COMMENT("Change shell of account"),
                &vl_method_Chsh,
		SD_VARLINK_SYMBOL_COMMENT("Provide response for PAM_PROMPT_ECHO_*"),
                &vl_method_Conv,
		SD_VARLINK_SYMBOL_COMMENT("Update passwd and/or shadow file"),
		&vl_method_UpdatePasswdShadow,
 		SD_VARLINK_SYMBOL_COMMENT("Stop the daemon"),
                &vl_method_Quit,
		SD_VARLINK_SYMBOL_COMMENT("Check if the service is running"),
                &vl_method_Ping,
                SD_VARLINK_SYMBOL_COMMENT("Set the maximum log level"),
                &vl_method_SetLogLevel,
                SD_VARLINK_SYMBOL_COMMENT("Get current environment block"),
                &vl_method_GetEnvironment,
		SD_VARLINK_SYMBOL_COMMENT("Authentication failure"),
		&vl_error_AuthenticationFailed,
		SD_VARLINK_SYMBOL_COMMENT("No entry found"),
                &vl_error_NoEntryFound,
		SD_VARLINK_SYMBOL_COMMENT("Invalid parameter for varlink function call"),
                &vl_error_InvalidParameter,
		SD_VARLINK_SYMBOL_COMMENT("Invalid shell"),
                &vl_error_InvalidShell,
		SD_VARLINK_SYMBOL_COMMENT("Password change aborted"),
		&vl_error_PasswordChangeAborted,
		SD_VARLINK_SYMBOL_COMMENT("Permission denied"),
		&vl_error_PermissionDenied,
		SD_VARLINK_SYMBOL_COMMENT("Internal Error"),
		&vl_error_InternalError);
