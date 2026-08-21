/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/basic_types.h"

#include <QtCore/QByteArray>
#include <QtCore/QJsonObject>
#include <QtCore/QString>
#include <QtCore/QStringList>

#include <optional>

namespace Core {

enum class VlessProfileError {
	None,
	Empty,
	TooLong,
	InvalidUri,
	InvalidUser,
	InvalidUserId,
	InvalidHost,
	InvalidPort,
	InvalidQuery,
	DuplicateParameter,
	UnsupportedParameter,
	UnsupportedEncryption,
	UnsupportedFlow,
	UnsupportedTransport,
	UnsupportedHeader,
	UnsupportedSecurity,
	InvalidTransportSettings,
	InvalidSecuritySettings,
	InvalidJson,
	InvalidServerName,
	UnsupportedFingerprint,
	InvalidAlpn,
	InvalidCertificatePin,
	InvalidVerifyName,
	InvalidPublicKey,
	InvalidShortId,
	InvalidMldsaVerify,
	InvalidSpiderPath,
	InvalidLocalSocksPort,
};

struct VlessProfileResult;

struct VlessLocalInbound final {
	uint16 port = 0;
	QString user;
	QString password;
};

struct VlessProfile final {
	QString endpointHost;
	uint16 endpointPort = 0;

	[[nodiscard]] QByteArray xrayConfig(
		const VlessLocalInbound &socks,
		const VlessLocalInbound &http) const;

private:
	QString _userId;
	QString _encryption;
	QString _flow;
	QString _transport;
	QString _security;
	QString _path;
	QString _transportHost;
	int _kcpMtu = 0;
	int _kcpTti = 0;
	QString _grpcServiceName;
	QString _grpcMode;
	QString _grpcAuthority;
	QString _xhttpMode;
	QJsonObject _xhttpExtra;
	bool _hasXhttpExtra = false;
	QJsonObject _finalMask;
	bool _hasFinalMask = false;
	QString _serverName;
	QString _fingerprint;
	QStringList _alpn;
	QString _ech;
	bool _hasEch = false;
	QString _pinnedPeerCertSha256;
	bool _hasPinnedPeerCertSha256 = false;
	QString _verifyPeerCertByName;
	bool _hasVerifyPeerCertByName = false;
	QString _publicKey;
	QString _shortId;
	bool _hasShortId = false;
	QString _mldsa65Verify;
	bool _hasMldsa65Verify = false;
	QString _spiderX;
	bool _hasSpiderX = false;

	friend VlessProfileResult ParseVlessProfile(QStringView uri);
};

struct VlessProfileResult final {
	std::optional<VlessProfile> profile;
	VlessProfileError error = VlessProfileError::None;

	[[nodiscard]] explicit operator bool() const {
		return profile.has_value();
	}
};

[[nodiscard]] VlessProfileResult ParseVlessProfile(QStringView uri);

} // namespace Core
