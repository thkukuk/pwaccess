// SPDX-License-Identifier: GPL-2.0-or-later

#include "varlink-org.openSUSE.pwaccess.h"

static SD_VARLINK_DEFINE_STRUCT_TYPE(MapRange,
				     SD_VARLINK_FIELD_COMMENT("struct map_range"),
				     SD_VARLINK_DEFINE_FIELD(upper, SD_VARLINK_INT,    0),
				     SD_VARLINK_DEFINE_FIELD(lower, SD_VARLINK_INT,    0),
				     SD_VARLINK_DEFINE_FIELD(count, SD_VARLINK_INT,    0));

static SD_VARLINK_DEFINE_METHOD(
		WriteMappings,
                SD_VARLINK_FIELD_COMMENT("PID for which to set the map range"),
                SD_VARLINK_DEFINE_INPUT(PID, SD_VARLINK_INT, 0),
		SD_VARLINK_FIELD_COMMENT("Which map to use: 'uid_map' or 'gid_map'"),
                SD_VARLINK_DEFINE_INPUT(Map, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The map ranges"),
		SD_VARLINK_DEFINE_INPUT_BY_TYPE(MapRanges, MapRange, SD_VARLINK_ARRAY),
		SD_VARLINK_FIELD_COMMENT("If call succeeded"),
                SD_VARLINK_DEFINE_OUTPUT(Success, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("Error Message"),
                SD_VARLINK_DEFINE_OUTPUT(ErrorMsg, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

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

static SD_VARLINK_DEFINE_ERROR(PermissionDenied);
static SD_VARLINK_DEFINE_ERROR(InvalidParameter);
static SD_VARLINK_DEFINE_ERROR(InternalError);

SD_VARLINK_DEFINE_INTERFACE(
                org_openSUSE_newidmapd,
                "org.openSUSE.newidmapd",
		SD_VARLINK_INTERFACE_COMMENT("newidmapd control APIs"),
		SD_VARLINK_SYMBOL_COMMENT("Describe map_range entry"),
		&vl_type_MapRange,
		SD_VARLINK_SYMBOL_COMMENT("Set map ranges"),
                &vl_method_WriteMappings,
 		SD_VARLINK_SYMBOL_COMMENT("Stop the daemon"),
                &vl_method_Quit,
		SD_VARLINK_SYMBOL_COMMENT("Check if the service is running."),
                &vl_method_Ping,
                SD_VARLINK_SYMBOL_COMMENT("Set the maximum log level."),
                &vl_method_SetLogLevel,
                SD_VARLINK_SYMBOL_COMMENT("Get current environment block."),
                &vl_method_GetEnvironment,
		SD_VARLINK_SYMBOL_COMMENT("Permission Denied"),
		&vl_error_PermissionDenied,
		SD_VARLINK_SYMBOL_COMMENT("Invalid parameter for varlink function call"),
                &vl_error_InvalidParameter,
		SD_VARLINK_SYMBOL_COMMENT("Internal Error"),
		&vl_error_InternalError);
