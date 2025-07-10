//SPDX-License-Identifier: GPL-2.0-or-later

#include "varlink-org.openSUSE.pwaccess.h"

static SD_VARLINK_DEFINE_STRUCT_TYPE(PasswdEntry,
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
		GetUserRecord,
                SD_VARLINK_FIELD_COMMENT("The numeric 32bit UNIX UID of the record, if look-up by UID is desired."),
                SD_VARLINK_DEFINE_INPUT(uid, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The UNIX user name of the record, if look-up by name is desired."),
                SD_VARLINK_DEFINE_INPUT(userName, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
		SD_VARLINK_FIELD_COMMENT("passwd entry"),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(passwd, PasswdEntry, SD_VARLINK_NULLABLE),
		SD_VARLINK_FIELD_COMMENT("shadow entry"),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(shadow, ShadowEntry, SD_VARLINK_NULLABLE),
		SD_VARLINK_FIELD_COMMENT("If all data got replied (depends on UID)"),
                SD_VARLINK_DEFINE_OUTPUT(Complete, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
		SD_VARLINK_FIELD_COMMENT("If call succeeded"),
                SD_VARLINK_DEFINE_OUTPUT(Success, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("Error Message"),
                SD_VARLINK_DEFINE_OUTPUT(ErrorMsg, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                GetGroupRecord,
                SD_VARLINK_FIELD_COMMENT("The numeric 32bit UNIX GID of the record, if look-up by GID is desired."),
                SD_VARLINK_DEFINE_INPUT(gid, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The UNIX group name of the record, if look-up by name is desired."),
                SD_VARLINK_DEFINE_INPUT(groupName, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                VerifyPassword,
                SD_VARLINK_FIELD_COMMENT("The account of the user to verify the password."),
                SD_VARLINK_DEFINE_INPUT(userName, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The password of the user to verify."),
                SD_VARLINK_DEFINE_INPUT(password, SD_VARLINK_STRING, 0),
		SD_VARLINK_FIELD_COMMENT("If empty password is ok, default false"),
                SD_VARLINK_DEFINE_INPUT(nullOK, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                ExpiredCheck,
                SD_VARLINK_FIELD_COMMENT("The account to check if expired."),
                SD_VARLINK_DEFINE_INPUT(userName, SD_VARLINK_STRING, 0));

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

SD_VARLINK_DEFINE_INTERFACE(
                org_openSUSE_pwaccess,
                "org.openSUSE.pwaccess",
		SD_VARLINK_INTERFACE_COMMENT("PWAccessD control APIs"),
		SD_VARLINK_SYMBOL_COMMENT("Get user entries from passwd and shadow"),
                &vl_method_GetUserRecord,
		SD_VARLINK_SYMBOL_COMMENT("Get group entries from group and gshadow"),
                &vl_method_GetGroupRecord,
		SD_VARLINK_SYMBOL_COMMENT("Verify password of account"),
                &vl_method_VerifyPassword,
		SD_VARLINK_SYMBOL_COMMENT("Check if account is expired"),
                &vl_method_ExpiredCheck,
 		SD_VARLINK_SYMBOL_COMMENT("Stop the daemon"),
                &vl_method_Quit,
		SD_VARLINK_SYMBOL_COMMENT("Check if the service is running."),
                &vl_method_Ping,
                SD_VARLINK_SYMBOL_COMMENT("Set the maximum log level."),
                &vl_method_SetLogLevel,
                SD_VARLINK_SYMBOL_COMMENT("Get current environment block."),
                &vl_method_GetEnvironment,
		SD_VARLINK_SYMBOL_COMMENT("No entry found"),
                &vl_error_NoEntryFound,
		SD_VARLINK_SYMBOL_COMMENT("Invalid parameter for varlink function call"),
                &vl_error_InvalidParameter,
		SD_VARLINK_SYMBOL_COMMENT("Internal Error"),
		&vl_error_InternalError);
