/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/const_string.h"

#define TDESKTOP_REQUESTED_ALPHA_VERSION (0ULL)

#ifdef TDESKTOP_ALLOW_CLOSED_ALPHA
#define TDESKTOP_ALPHA_VERSION TDESKTOP_REQUESTED_ALPHA_VERSION
#else // TDESKTOP_ALLOW_CLOSED_ALPHA
#define TDESKTOP_ALPHA_VERSION (0ULL)
#endif // TDESKTOP_ALLOW_CLOSED_ALPHA

// used in Updater.cpp and Setup.iss for Windows
constexpr auto AppId = "{6D9D7D0B-4EC7-4E1B-85E4-7762FDF86255}"_cs;
constexpr auto AppName = "TeVLESS"_cs;
constexpr auto AppFile = "tevless"_cs;
constexpr auto AppLinuxId = "io.github.gustafsonhelga1980_bit.tevless"_cs;
constexpr auto AppProjectUrl =
	"https://github.com/gustafsonhelga1980-bit/tevless"_cs;
constexpr auto AppSupportUrl =
	"https://github.com/gustafsonhelga1980-bit/tevless/issues"_cs;
constexpr auto AppReleasesUrl =
	"https://github.com/gustafsonhelga1980-bit/tevless/releases"_cs;
constexpr auto AppLicenseUrl =
	"https://github.com/gustafsonhelga1980-bit/tevless/blob/main/LICENSE"_cs;
constexpr auto AppUpstreamUrl =
	"https://github.com/telegramdesktop/tdesktop"_cs;
constexpr auto AppReleaseVersion = "0.1.0-beta.1"_cs;
constexpr auto AppVersion = 7000009;
constexpr auto AppVersionStr = "7.0.9";
constexpr auto AppBetaVersion = false;
constexpr auto AppAlphaVersion = TDESKTOP_ALPHA_VERSION;
