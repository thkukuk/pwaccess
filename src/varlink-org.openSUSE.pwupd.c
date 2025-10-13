// SPDX-License-Identifier: GPL-2.0-or-later

#include "varlink-org.openSUSE.pwupd.h"

static SD_VARLINK_DEFINE_METHOD(
                Chsh,
                SD_VARLINK_FIELD_COMMENT("The account of the user to change the shell."),
                SD_VARLINK_DEFINE_INPUT(userName, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The new shell of the user."),
                SD_VARLINK_DEFINE_INPUT(shell, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD(
                Chauthtok,
                SD_VARLINK_FIELD_COMMENT("The account of the user to change the password."),
                SD_VARLINK_DEFINE_INPUT(userName, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD(
		Conv,
                SD_VARLINK_FIELD_COMMENT("Response for PAM_PROMPT_ECHO_*."),
                SD_VARLINK_DEFINE_INPUT(response, SD_VARLINK_STRING, 0));

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

SD_VARLINK_DEFINE_INTERFACE(
                org_openSUSE_pwupd,
                "org.openSUSE.pwupd",
		SD_VARLINK_INTERFACE_COMMENT("PWUpdD control APIs"),
		SD_VARLINK_SYMBOL_COMMENT("Change shell of account"),
                &vl_method_Chsh,
		SD_VARLINK_SYMBOL_COMMENT("Provide response for PAM_PROMPT_ECHO_*"),
                &vl_method_Conv,
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
		SD_VARLINK_SYMBOL_COMMENT("Invalid shell"),
                &vl_error_InvalidShell,
		SD_VARLINK_SYMBOL_COMMENT("Internal Error"),
		&vl_error_InternalError);
