/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "core/vless_profile.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QElapsedTimer>
#include <QtCore/QFileInfo>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QProcess>
#include <QtCore/QProcessEnvironment>
#include <QtCore/QThread>
#include <QtCore/QUrl>
#include <QtNetwork/QHostAddress>
#include <QtNetwork/QNetworkProxy>
#include <QtNetwork/QTcpServer>
#include <QtNetwork/QTcpSocket>

#include <algorithm>
#include <iostream>
#include <optional>
#include <vector>

namespace {

constexpr auto kLocalPort = 10808;
constexpr auto kLocalHttpPort = 10809;
constexpr auto kRuntimeTimeout = 5000;
constexpr auto kProbeTimeout = 1500;
constexpr auto kMaxHttpResponseBytes = 4096;

[[nodiscard]] Core::VlessLocalInbound SyntheticSocksInbound() {
	return {
		.port = kLocalPort,
		.user = u"synthetic-user"_q,
		.password = u"synthetic-password"_q,
	};
}

[[nodiscard]] Core::VlessLocalInbound SyntheticHttpInbound() {
	return {
		.port = kLocalHttpPort,
		.user = u"synthetic-web-user"_q,
		.password = u"synthetic-web-password"_q,
	};
}

struct RejectedUrl final {
	const char *name = nullptr;
	QString url;
	Core::VlessProfileError error = Core::VlessProfileError::None;
};

auto Failures = 0;

void Check(bool condition, const char *message) {
	if (!condition) {
		std::cerr << "FAILED: " << message << '\n';
		++Failures;
	}
}

struct HttpResponse final {
	int status = 0;
	QByteArray headers;
};

[[nodiscard]] int Remaining(
		const QElapsedTimer &timer,
		int timeout) {
	return std::max(0, timeout - int(timer.elapsed()));
}

[[nodiscard]] HttpResponse ConnectThroughHttpProxy(
		quint16 proxyPort,
		quint16 destinationPort,
		const QByteArray &authorization = {}) {
	auto socket = QTcpSocket();
	socket.setProxy(QNetworkProxy::NoProxy);
	auto timer = QElapsedTimer();
	timer.start();
	socket.connectToHost(QHostAddress::LocalHost, proxyPort);
	if (!socket.waitForConnected(Remaining(timer, kProbeTimeout))) {
		return {};
	}

	const auto authority = QByteArray("127.0.0.1:")
		+ QByteArray::number(destinationPort);
	auto request = QByteArray("CONNECT ")
		+ authority
		+ " HTTP/1.1\r\nHost: "
		+ authority
		+ "\r\nProxy-Connection: close\r\n";
	if (!authorization.isEmpty()) {
		request += "Proxy-Authorization: Basic "
			+ authorization.toBase64()
			+ "\r\n";
	}
	request += "\r\n";
	if (socket.write(request) != request.size()
		|| (socket.bytesToWrite() > 0
			&& !socket.waitForBytesWritten(
				Remaining(timer, kProbeTimeout)))) {
		return {};
	}

	auto response = QByteArray();
	while (!response.contains("\r\n\r\n")
		&& response.size() <= kMaxHttpResponseBytes) {
		const auto remaining = Remaining(timer, kProbeTimeout);
		if (!remaining) {
			break;
		}
		if (!socket.bytesAvailable() && !socket.waitForReadyRead(remaining)) {
			response += socket.readAll();
			break;
		}
		response += socket.readAll();
	}
	const auto headerEnd = response.indexOf("\r\n\r\n");
	if (headerEnd < 0 || headerEnd > kMaxHttpResponseBytes) {
		return {};
	}
	response.truncate(headerEnd + 4);
	const auto statusEnd = response.indexOf("\r\n");
	const auto fields = response.left(statusEnd).split(' ');
	bool validStatus = false;
	const auto status = (fields.size() >= 2)
		? fields.at(1).toInt(&validStatus)
		: 0;
	return {
		.status = validStatus ? status : 0,
		.headers = std::move(response),
	};
}

[[nodiscard]] bool HasBasicProxyChallenge(const QByteArray &headers) {
	for (const auto &line : headers.split('\n')) {
		const auto separator = line.indexOf(':');
		if (separator > 0
			&& line.left(separator).trimmed().toLower()
				== "proxy-authenticate"
			&& line.mid(separator + 1).trimmed().toLower()
				.startsWith("basic")) {
			return true;
		}
	}
	return false;
}

[[nodiscard]] bool StopXray(QProcess &process) {
	if (process.state() == QProcess::NotRunning) {
		return true;
	}
	process.terminate();
	if (process.waitForFinished(3000)) {
		return true;
	}
	process.kill();
	process.waitForFinished(1000);
	return false;
}

[[nodiscard]] QString Scheme() {
	return u"vless"_q + u"://"_q;
}

[[nodiscard]] QString UserId() {
	return u"123e4567-e89b-42d3-a456-426614174000"_q;
}

[[nodiscard]] QString PublicKey() {
	return u"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"_q;
}

[[nodiscard]] QString Encode(const QString &value) {
	return QString::fromLatin1(QUrl::toPercentEncoding(value));
}

[[nodiscard]] QString MakeUrl(
		const QStringList &query,
		const QString &fragment = u"synthetic"_q) {
	return Scheme()
		+ UserId()
		+ u"@edge.proxy.invalid:443?"_q
		+ query.join('&')
		+ (fragment.isNull() ? QString() : (u"#"_q + fragment));
}

[[nodiscard]] QStringList RealityQuery(const QString &transport) {
	return {
		u"encryption=none"_q,
		u"security=reality"_q,
		u"sni=front.proxy.invalid"_q,
		u"fp=chrome"_q,
		u"pbk="_q + PublicKey(),
		u"sid=0123456789abcdef"_q,
		u"type="_q + transport,
	};
}

[[nodiscard]] QStringList TlsQuery(const QString &transport) {
	return {
		u"encryption=none"_q,
		u"security=tls"_q,
		u"sni=front.proxy.invalid"_q,
		u"fp=chrome"_q,
		u"type="_q + transport,
	};
}

[[nodiscard]] QString With(
		QStringList query,
		const QString &field) {
	query.push_back(field);
	return MakeUrl(query);
}

[[nodiscard]] QString Replaced(
		const QString &source,
		const QString &before,
		const QString &after) {
	auto result = source;
	result.replace(before, after);
	return result;
}

[[nodiscard]] QJsonObject ObjectAt(
		const QJsonObject &object,
		const QString &key) {
	return object.value(key).toObject();
}

[[nodiscard]] QJsonObject FirstObjectAt(
		const QJsonObject &object,
		const QString &key) {
	const auto array = object.value(key).toArray();
	return array.isEmpty() ? QJsonObject() : array.at(0).toObject();
}

[[nodiscard]] bool ValidateWithXray(
		const QByteArray &config,
		const char *caseName) {
	const auto executable = qEnvironmentVariable("TDESKTOP_TEST_XRAY_PATH");
	if (executable.isEmpty()) {
		return true;
	}
	const auto info = QFileInfo(executable);
	if (!info.isFile() || !info.isExecutable()) {
		std::cerr << "FAILED: unavailable Xray validator for " << caseName << '\n';
		return false;
	}
	auto process = QProcess();
	process.setProgram(info.canonicalFilePath());
	process.setArguments({
		u"run"_q,
		u"-test"_q,
		u"-format"_q,
		u"json"_q,
		u"-c"_q,
		u"stdin:"_q,
	});
	auto environment = QProcessEnvironment::systemEnvironment();
	environment.insert(u"XRAY_LOCATION_ASSET"_q, info.absolutePath());
	process.setProcessEnvironment(environment);
	process.setStandardOutputFile(QProcess::nullDevice());
	process.setStandardErrorFile(QProcess::nullDevice());
	process.start(QIODevice::ReadWrite);
	if (!process.waitForStarted(5000)) {
		std::cerr << "FAILED: Xray did not start for " << caseName << '\n';
		return false;
	}
	const auto accepted = process.write(config);
	process.closeWriteChannel();
	if (accepted != config.size() || !process.waitForFinished(5000)) {
		process.kill();
		process.waitForFinished(1000);
		std::cerr << "FAILED: Xray validation timed out for " << caseName << '\n';
		return false;
	}
	if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
		std::cerr << "FAILED: Xray rejected " << caseName << '\n';
		return false;
	}
	return true;
}

void CheckCommonConfig(const QJsonObject &root) {
	const auto log = ObjectAt(root, u"log"_q);
	Check(log.value(u"access"_q) == u"none"_q, "disabled Xray access log");
	const auto inbounds = root.value(u"inbounds"_q).toArray();
	Check(inbounds.size() == 2, "generated two inbound objects");
	if (inbounds.size() != 2) {
		return;
	}
	const auto inbound = inbounds.at(0).toObject();
	Check(inbound.value(u"listen"_q) == u"127.0.0.1"_q, "bound to loopback");
	Check(inbound.value(u"port"_q).toInt() == kLocalPort, "used local port");
	Check(inbound.value(u"protocol"_q) == u"socks"_q, "used SOCKS inbound");
	const auto settings = ObjectAt(inbound, u"settings"_q);
	Check(settings.value(u"auth"_q) == u"password"_q, "required SOCKS auth");
	Check(settings.value(u"udp"_q) == true, "enabled SOCKS UDP");
	const auto accounts = settings.value(u"accounts"_q).toArray();
	Check(accounts.size() == 1, "generated one SOCKS account");
	if (accounts.size() == 1) {
		const auto account = accounts.at(0).toObject();
		Check(account.value(u"user"_q) == u"synthetic-user"_q,
			"preserved SOCKS user");
		Check(account.value(u"pass"_q) == u"synthetic-password"_q,
			"preserved SOCKS password");
	}
	const auto http = inbounds.at(1).toObject();
	Check(http.value(u"listen"_q) == u"127.0.0.1"_q,
		"bound HTTP proxy to loopback");
	Check(http.value(u"port"_q).toInt() == kLocalHttpPort,
		"used local HTTP port");
	Check(http.value(u"protocol"_q) == u"http"_q,
		"used HTTP proxy inbound");
	const auto httpSettings = ObjectAt(http, u"settings"_q);
	Check(httpSettings.value(u"allowTransparent"_q) == false,
		"disabled transparent HTTP forwarding");
	const auto httpAccounts = httpSettings.value(u"accounts"_q).toArray();
	Check(httpAccounts.size() == 1, "generated one HTTP proxy account");
	if (httpAccounts.size() == 1) {
		const auto user = httpAccounts.at(0).toObject();
		Check(user.value(u"user"_q) == u"synthetic-web-user"_q,
			"preserved HTTP proxy user");
		Check(user.value(u"pass"_q) == u"synthetic-web-password"_q,
			"preserved HTTP proxy password");
	}
	const auto outbounds = root.value(u"outbounds"_q).toArray();
	Check(outbounds.size() == 1, "generated one outbound");
	if (outbounds.size() != 1) {
		return;
	}
	const auto outbound = outbounds.at(0).toObject();
	Check(outbound.value(u"protocol"_q) == u"vless"_q, "used VLESS outbound");
	const auto destination = FirstObjectAt(
		ObjectAt(outbound, u"settings"_q),
		u"vnext"_q);
	Check(destination.value(u"address"_q) == u"edge.proxy.invalid"_q,
		"preserved destination host");
	Check(destination.value(u"port"_q).toInt() == 443,
		"preserved destination port");
	const auto user = FirstObjectAt(destination, u"users"_q);
	Check(user.value(u"id"_q) == UserId(), "preserved VLESS user ID");
}

[[nodiscard]] std::optional<QJsonObject> Generated(
		const QString &url,
		const char *caseName,
		bool validateWithXray = true) {
	const auto parsed = Core::ParseVlessProfile(url);
	if (!parsed || !parsed.profile) {
		std::cerr << "FAILED: rejected accepted case " << caseName
			<< " with error " << int(parsed.error) << '\n';
		++Failures;
		return std::nullopt;
	}
	auto config = parsed.profile->xrayConfig(
		SyntheticSocksInbound(),
		SyntheticHttpInbound());
	QJsonParseError error;
	const auto document = QJsonDocument::fromJson(config, &error);
	if (error.error != QJsonParseError::NoError || !document.isObject()) {
		std::cerr << "FAILED: invalid generated JSON for " << caseName << '\n';
		++Failures;
		return std::nullopt;
	}
	const auto root = document.object();
	CheckCommonConfig(root);
	if (validateWithXray && !ValidateWithXray(config, caseName)) {
		++Failures;
	}
	config.fill('\0');
	return root;
}

[[nodiscard]] QJsonObject StreamAt(const QJsonObject &root) {
	return ObjectAt(FirstObjectAt(root, u"outbounds"_q), u"streamSettings"_q);
}

void CheckTransport(
		const QJsonObject &root,
		const QString &network,
		const QString &settingsKey) {
	const auto stream = StreamAt(root);
	Check(stream.value(u"network"_q) == network, "normalized transport network");
	for (const auto &key : {
		u"kcpSettings"_q,
		u"wsSettings"_q,
		u"grpcSettings"_q,
		u"httpupgradeSettings"_q,
		u"xhttpSettings"_q,
	}) {
		Check(stream.contains(key) == (key == settingsKey),
			"emitted only matching transport settings");
	}
}

void CheckRejected(const RejectedUrl &test) {
	const auto parsed = Core::ParseVlessProfile(test.url);
	if (parsed) {
		std::cerr << "FAILED: accepted rejected case " << test.name << '\n';
		++Failures;
	}
	if (parsed.error != test.error) {
		std::cerr << "FAILED: unexpected error for " << test.name
			<< ": got " << int(parsed.error)
			<< ", expected " << int(test.error) << '\n';
		++Failures;
	}
}

void CheckRawReality() {
	auto query = RealityQuery(u"raw"_q);
	query.push_back(u"flow=xtls-rprx-vision"_q);
	query.push_back(u"headerType=none"_q);
	query.push_back(u"spx=%2F"_q);
	const auto root = Generated(MakeUrl(query), "raw-reality");
	if (!root) {
		return;
	}
	CheckTransport(*root, u"raw"_q, QString());
	const auto stream = StreamAt(*root);
	Check(stream.value(u"security"_q) == u"reality"_q,
		"generated REALITY security");
	Check(!stream.contains(u"tlsSettings"_q), "did not emit TLS under REALITY");
	const auto reality = ObjectAt(stream, u"realitySettings"_q);
	Check(reality.value(u"serverName"_q) == u"front.proxy.invalid"_q,
		"preserved REALITY SNI");
	Check(reality.value(u"fingerprint"_q) == u"chrome"_q,
		"preserved REALITY fingerprint");
	Check(reality.value(u"password"_q) == PublicKey(),
		"preserved REALITY public key");
	Check(reality.value(u"spiderX"_q) == u"/"_q,
		"decoded REALITY spider path");
	const auto user = FirstObjectAt(
		FirstObjectAt(ObjectAt(
			FirstObjectAt(*root, u"outbounds"_q),
			u"settings"_q),
			u"vnext"_q),
		u"users"_q);
	Check(user.value(u"flow"_q) == u"xtls-rprx-vision"_q,
		"preserved Vision flow");

	const auto tcp = Generated(
		Replaced(MakeUrl(query), u"type=raw"_q, u"type=tcp"_q),
		"tcp-alias",
		false);
	if (tcp) {
		CheckTransport(*tcp, u"raw"_q, QString());
	}
}

void CheckGrpcReality() {
	auto query = RealityQuery(u"grpc"_q);
	query.push_back(u"serviceName=%2Fsynthetic%2Fgrpc"_q);
	query.push_back(u"authority=authority.proxy.invalid"_q);
	query.push_back(u"mode=gun"_q);
	query.push_back(u"alpn=h2"_q);
	const auto root = Generated(MakeUrl(query), "grpc-reality");
	if (!root) {
		return;
	}
	CheckTransport(*root, u"grpc"_q, u"grpcSettings"_q);
	const auto stream = StreamAt(*root);
	const auto grpc = ObjectAt(stream, u"grpcSettings"_q);
	Check(grpc.value(u"serviceName"_q) == u"/synthetic/grpc"_q,
		"decoded gRPC service name");
	Check(grpc.value(u"authority"_q) == u"authority.proxy.invalid"_q,
		"preserved gRPC authority");
	Check(grpc.value(u"multiMode"_q) == false, "mapped gRPC gun mode");
	Check(!ObjectAt(stream, u"realitySettings"_q).contains(u"alpn"_q),
		"treated REALITY ALPN as compatibility metadata");

	const auto plus = Generated(
		With(RealityQuery(u"grpc"_q), u"serviceName=a+b"_q),
		"grpc-plus",
		false);
	if (plus) {
		Check(ObjectAt(StreamAt(*plus), u"grpcSettings"_q)
			.value(u"serviceName"_q) == u"a+b"_q,
			"kept raw plus in share-link value");
	}

	const auto multi = Generated(
		With(RealityQuery(u"grpc"_q), u"mode=multi"_q),
		"grpc-multi");
	if (multi) {
		Check(ObjectAt(StreamAt(*multi), u"grpcSettings"_q)
			.value(u"multiMode"_q) == true,
			"mapped gRPC multi mode");
	}
}

void CheckTlsTransports() {
	auto wsQuery = TlsQuery(u"ws"_q);
	wsQuery.push_back(u"path=%2Fsocket%3Fed%3D2560"_q);
	wsQuery.push_back(u"host=front.proxy.invalid"_q);
	wsQuery.push_back(u"alpn=http%2F1.1"_q);
	const auto websocket = Generated(MakeUrl(wsQuery), "websocket-tls");
	if (websocket) {
		CheckTransport(*websocket, u"websocket"_q, u"wsSettings"_q);
		const auto settings = ObjectAt(StreamAt(*websocket), u"wsSettings"_q);
		Check(settings.value(u"path"_q) == u"/socket?ed=2560"_q,
			"preserved WebSocket early-data path");
		Check(ObjectAt(StreamAt(*websocket), u"tlsSettings"_q)
			.value(u"alpn"_q).toArray().at(0) == u"http/1.1"_q,
			"mapped TLS ALPN array");
	}

	const auto upgrade = Generated(
		With(TlsQuery(u"httpupgrade"_q), u"path=%2Fupgrade"_q),
		"httpupgrade-tls");
	if (upgrade) {
		CheckTransport(
			*upgrade,
			u"httpupgrade"_q,
			u"httpupgradeSettings"_q);
	}

	auto kcpQuery = TlsQuery(u"kcp"_q);
	kcpQuery.push_back(u"mtu=1350"_q);
	kcpQuery.push_back(u"tti=50"_q);
	kcpQuery.push_back(u"headerType=none"_q);
	const auto kcp = Generated(MakeUrl(kcpQuery), "mkcp-tls");
	if (kcp) {
		CheckTransport(*kcp, u"mkcp"_q, u"kcpSettings"_q);
		const auto settings = ObjectAt(StreamAt(*kcp), u"kcpSettings"_q);
		Check(settings.value(u"mtu"_q).toInt() == 1350, "mapped mKCP MTU");
		Check(settings.value(u"tti"_q).toInt() == 50, "mapped mKCP TTI");
	}
}

void CheckXhttpAndFinalMask() {
	const auto extra = Encode(
		uR"({"headers":{"X-Synthetic":"ok"},"xmux":{"maxConcurrency":"1-2"}})"_q);
	auto query = RealityQuery(u"xhttp"_q);
	query.push_back(u"path=%2Fxhttp"_q);
	query.push_back(u"host=front.proxy.invalid"_q);
	query.push_back(u"mode=stream-one"_q);
	query.push_back(u"extra="_q + extra);
	const auto root = Generated(MakeUrl(query), "xhttp-reality");
	if (root) {
		CheckTransport(*root, u"xhttp"_q, u"xhttpSettings"_q);
		const auto settings = ObjectAt(StreamAt(*root), u"xhttpSettings"_q);
		Check(settings.value(u"mode"_q) == u"stream-one"_q,
			"mapped XHTTP mode");
		Check(settings.value(u"extra"_q).isObject(),
			"emitted scoped XHTTP extra object");
	}

	const auto mask = Encode(
		uR"({"tcp":[{"type":"fragment","settings":{"length":"10-20"}}]})"_q);
	const auto masked = Generated(
		With(RealityQuery(u"raw"_q), u"fm="_q + mask),
		"finalmask-fragment");
	if (masked) {
		Check(StreamAt(*masked).value(u"finalmask"_q).isObject(),
			"emitted FinalMask inside stream settings");
	}
}

void CheckEncryptedNoneSecurity() {
	const auto encryption = u"mlkem768x25519plus.native.0rtt."_q + PublicKey();
	const auto root = Generated(MakeUrl({
		u"encryption="_q + encryption,
		u"security=none"_q,
		u"type=raw"_q,
	}), "mlkem-none");
	if (!root) {
		return;
	}
	const auto stream = StreamAt(*root);
	Check(stream.value(u"security"_q) == u"none"_q,
		"allowed none security with VLESS encryption");
	Check(!stream.contains(u"tlsSettings"_q)
		&& !stream.contains(u"realitySettings"_q),
		"omitted security-specific settings for none");
}

void CheckRejections() {
	const auto raw = MakeUrl(RealityQuery(u"raw"_q));
	const auto grpc = MakeUrl(RealityQuery(u"grpc"_q));
	const auto wsTls = MakeUrl(TlsQuery(u"ws"_q));
	const auto invalidExtra = Encode(
		uR"({"downloadSettings":{"network":"raw"}})"_q);
	const auto oversizedPadding = Encode(
		uR"({"xPaddingBytes":1000000000})"_q);
	const auto invalidHeader = Encode(
		uR"({"headers":{"bad:name":"value"}})"_q);
	const auto invalidMethod = Encode(
		uR"({"uplinkHTTPMethod":"BAD:METHOD"})"_q);
	const auto invalidPaddingHeader = Encode(
		uR"({"xPaddingHeader":"bad:name"})"_q);
	const auto invalidSessionKey = Encode(
		uR"({"sessionPlacement":"header","sessionKey":"bad:name"})"_q);
	const auto invalidMask = Encode(
		uR"({"tcp":[{"type":"unknown"}]})"_q);
	const auto invalidSudoku = Encode(
		uR"({"tcp":[{"type":"sudoku","settings":{"ascii":"unknown"}}]})"_q);
	const auto rejected = std::vector<RejectedUrl>{
		{
			"wrong scheme",
			Replaced(raw, Scheme(), u"https://"_q),
			Core::VlessProfileError::InvalidUri,
		},
		{
			"invalid UUID",
			Replaced(raw, UserId(), u"not-a-uuid"_q),
			Core::VlessProfileError::InvalidUserId,
		},
		{
			"password userinfo",
			Replaced(raw, UserId() + u"@"_q, UserId() + u":password@"_q),
			Core::VlessProfileError::InvalidUser,
		},
		{
			"duplicate decoded key",
			Replaced(
				raw,
				u"security=reality"_q,
				u"security=reality&%73ecurity=reality"_q),
			Core::VlessProfileError::DuplicateParameter,
		},
		{
			"unknown parameter",
			With(RealityQuery(u"raw"_q), u"unknown=value"_q),
			Core::VlessProfileError::UnsupportedParameter,
		},
		{
			"removed HTTP transport",
			MakeUrl(RealityQuery(u"http"_q)),
			Core::VlessProfileError::UnsupportedTransport,
		},
		{
			"removed QUIC transport",
			MakeUrl(RealityQuery(u"quic"_q)),
			Core::VlessProfileError::UnsupportedTransport,
		},
		{
			"REALITY WebSocket",
			MakeUrl(RealityQuery(u"ws"_q)),
			Core::VlessProfileError::UnsupportedSecurity,
		},
		{
			"naked VLESS",
			MakeUrl({
				u"encryption=none"_q,
				u"security=none"_q,
				u"type=raw"_q,
			}),
			Core::VlessProfileError::UnsupportedSecurity,
		},
		{
			"gRPC explicit empty service",
			With(RealityQuery(u"grpc"_q), u"serviceName="_q),
			Core::VlessProfileError::InvalidTransportSettings,
		},
		{
			"gRPC service on raw",
			With(RealityQuery(u"raw"_q), u"serviceName=wrong"_q),
			Core::VlessProfileError::UnsupportedParameter,
		},
		{
			"unrepresentable gRPC mode",
			With(RealityQuery(u"grpc"_q), u"mode=guna"_q),
			Core::VlessProfileError::InvalidTransportSettings,
		},
		{
			"Vision on gRPC",
			With(RealityQuery(u"grpc"_q), u"flow=xtls-rprx-vision"_q),
			Core::VlessProfileError::UnsupportedFlow,
		},
		{
			"empty WebSocket path",
			With(TlsQuery(u"ws"_q), u"path="_q),
			Core::VlessProfileError::InvalidTransportSettings,
		},
		{
			"mKCP MTU below documented range",
			With(TlsQuery(u"kcp"_q), u"mtu=500"_q),
			Core::VlessProfileError::InvalidTransportSettings,
		},
		{
			"removed mKCP header",
			With(TlsQuery(u"kcp"_q), u"headerType=srtp"_q),
			Core::VlessProfileError::UnsupportedHeader,
		},
		{
			"wrong gRPC ALPN",
			With(RealityQuery(u"grpc"_q), u"alpn=http%2F1.1"_q),
			Core::VlessProfileError::InvalidAlpn,
		},
		{
			"malformed REALITY key",
			Replaced(raw, PublicKey(), u"bad-key"_q),
			Core::VlessProfileError::InvalidPublicKey,
		},
		{
			"odd REALITY short ID",
			Replaced(raw, u"sid=0123456789abcdef"_q, u"sid=123"_q),
			Core::VlessProfileError::InvalidShortId,
		},
		{
			"unsafe XHTTP extra",
			With(RealityQuery(u"xhttp"_q), u"extra="_q + invalidExtra),
			Core::VlessProfileError::InvalidJson,
		},
		{
			"resource-intensive XHTTP padding",
			With(RealityQuery(u"xhttp"_q), u"extra="_q + oversizedPadding),
			Core::VlessProfileError::InvalidJson,
		},
		{
			"invalid XHTTP header name",
			With(RealityQuery(u"xhttp"_q), u"extra="_q + invalidHeader),
			Core::VlessProfileError::InvalidJson,
		},
		{
			"invalid XHTTP method token",
			With(RealityQuery(u"xhttp"_q), u"extra="_q + invalidMethod),
			Core::VlessProfileError::InvalidJson,
		},
		{
			"invalid XHTTP padding header",
			With(
				RealityQuery(u"xhttp"_q),
				u"extra="_q + invalidPaddingHeader),
			Core::VlessProfileError::InvalidJson,
		},
		{
			"invalid XHTTP placement key",
			With(RealityQuery(u"xhttp"_q), u"extra="_q + invalidSessionKey),
			Core::VlessProfileError::InvalidJson,
		},
		{
			"unknown FinalMask type",
			With(RealityQuery(u"raw"_q), u"fm="_q + invalidMask),
			Core::VlessProfileError::InvalidJson,
		},
		{
			"invalid Sudoku runtime mode",
			With(RealityQuery(u"raw"_q), u"fm="_q + invalidSudoku),
			Core::VlessProfileError::InvalidJson,
		},
		{
			"encoded control",
			With(RealityQuery(u"grpc"_q), u"serviceName=%00"_q),
			Core::VlessProfileError::InvalidQuery,
		},
	};
	for (const auto &test : rejected) {
		CheckRejected(test);
	}

	auto fields = RealityQuery(u"raw"_q);
	while (fields.size() < 33) {
		fields.push_back(u"sid="_q + QString::number(fields.size()));
	}
	CheckRejected({
		"too many query fields",
		MakeUrl(fields),
		Core::VlessProfileError::InvalidQuery,
	});

	auto maximum = raw.left(raw.indexOf('#') + 1);
	maximum += QString(8192 - maximum.toUtf8().size(), 'a');
	Check(bool(Core::ParseVlessProfile(maximum)), "accepted 8192-byte profile");
	CheckRejected({
		"8193-byte profile",
		maximum + u"a"_q,
		Core::VlessProfileError::TooLong,
	});

	Check(bool(Core::ParseVlessProfile(grpc)),
		"accepted gRPC without serviceName");
	Check(bool(Core::ParseVlessProfile(wsTls)), "accepted default WebSocket path");
}

void CheckCredentialLimits() {
	const auto parsed = Core::ParseVlessProfile(MakeUrl(RealityQuery(u"raw"_q)));
	Check(bool(parsed.profile), "parsed credential-boundary fixture");
	if (!parsed.profile) {
		return;
	}
	const auto maximum = QString(255, 'a');
	const auto http = SyntheticHttpInbound();
	Check(!parsed.profile->xrayConfig({
		.port = kLocalPort,
		.user = maximum,
		.password = maximum,
	}, http).isEmpty(), "accepted 255-byte SOCKS credentials");
	Check(parsed.profile->xrayConfig(
		{
			.port = kLocalPort,
			.user = QString(256, 'a'),
			.password = maximum,
		},
		http).isEmpty(), "rejected 256-byte SOCKS username");
	Check(parsed.profile->xrayConfig(
		{
			.port = kLocalPort,
			.user = maximum,
			.password = QString(256, 'a'),
		},
		http).isEmpty(), "rejected 256-byte SOCKS password");
	Check(parsed.profile->xrayConfig({
		.port = kLocalPort,
		.password = maximum,
	}, http).isEmpty(), "rejected empty SOCKS username");
	Check(parsed.profile->xrayConfig(
		SyntheticSocksInbound(),
		{
			.port = kLocalHttpPort,
			.user = QString(256, 'a'),
			.password = maximum,
		}).isEmpty(), "rejected 256-byte HTTP username");
	Check(parsed.profile->xrayConfig(
		SyntheticSocksInbound(),
		{
			.port = kLocalHttpPort,
			.user = maximum,
			.password = QString(256, 'a'),
		}).isEmpty(), "rejected 256-byte HTTP password");
	Check(parsed.profile->xrayConfig(
		SyntheticSocksInbound(),
		{
			.port = kLocalPort,
			.user = maximum,
			.password = maximum,
		}).isEmpty(), "rejected duplicate local ports");
}

void CheckHttpProxyRuntime() {
	const auto executable = qEnvironmentVariable("TDESKTOP_TEST_XRAY_PATH");
	if (executable.isEmpty()) {
		return;
	}
	const auto info = QFileInfo(executable);
	if (!info.isFile() || !info.isExecutable()) {
		Check(false, "found executable Xray for HTTP proxy runtime test");
		return;
	}

	auto destination = QTcpServer();
	auto socksReservation = QTcpServer();
	auto httpReservation = QTcpServer();
	for (const auto server : {
		&destination,
		&socksReservation,
		&httpReservation,
	}) {
		server->setProxy(QNetworkProxy::NoProxy);
	}
	if (!destination.listen(QHostAddress::LocalHost, 0)
		|| !socksReservation.listen(QHostAddress::LocalHost, 0)
		|| !httpReservation.listen(QHostAddress::LocalHost, 0)) {
		Check(false, "reserved loopback ports for HTTP proxy runtime test");
		return;
	}
	const auto destinationPort = destination.serverPort();
	const auto socksPort = socksReservation.serverPort();
	const auto httpPort = httpReservation.serverPort();
	socksReservation.close();
	httpReservation.close();

	const auto parsed = Core::ParseVlessProfile(
		MakeUrl(RealityQuery(u"raw"_q)));
	if (!parsed || !parsed.profile) {
		Check(false, "parsed HTTP proxy runtime fixture");
		return;
	}
	const auto webUser = u"synthetic-runtime-web-user"_q;
	const auto webPassword = u"synthetic-runtime-web-password"_q;
	auto config = parsed.profile->xrayConfig(
		{
			.port = socksPort,
			.user = u"synthetic-runtime-socks-user"_q,
			.password = u"synthetic-runtime-socks-password"_q,
		},
		{
			.port = httpPort,
			.user = webUser,
			.password = webPassword,
		});
	auto document = QJsonDocument::fromJson(config);
	if (config.isEmpty() || !document.isObject()) {
		Check(false, "generated HTTP proxy runtime configuration");
		config.fill('\0');
		return;
	}
	auto root = document.object();
	root.insert(u"outbounds"_q, QJsonArray{
		QJsonObject{
			{ u"tag"_q, u"vless-out"_q },
			{ u"protocol"_q, u"freedom"_q },
			{ u"settings"_q, QJsonObject() },
		},
	});
	config.fill('\0');
	config = QJsonDocument(root).toJson(QJsonDocument::Compact);

	auto process = QProcess();
	process.setProgram(info.canonicalFilePath());
	process.setArguments({
		u"run"_q,
		u"-format"_q,
		u"json"_q,
		u"-c"_q,
		u"stdin:"_q,
	});
	auto environment = QProcessEnvironment::systemEnvironment();
	environment.insert(u"XRAY_LOCATION_ASSET"_q, info.absolutePath());
	process.setProcessEnvironment(environment);
	process.setStandardOutputFile(QProcess::nullDevice());
	process.setStandardErrorFile(QProcess::nullDevice());
	process.start(QIODevice::ReadWrite);
	if (!process.waitForStarted(kRuntimeTimeout)) {
		Check(false, "started Xray for HTTP proxy runtime test");
		config.fill('\0');
		return;
	}
	const auto configSize = config.size();
	const auto accepted = process.write(config);
	const auto written = (accepted == configSize)
		&& (process.bytesToWrite() == 0
			|| process.waitForBytesWritten(kRuntimeTimeout));
	process.closeWriteChannel();
	config.fill('\0');
	if (!written) {
		Check(false, "sent HTTP proxy runtime configuration to Xray");
		Check(StopXray(process), "reaped Xray after configuration failure");
		return;
	}

	auto startup = QElapsedTimer();
	startup.start();
	auto unauthenticated = HttpResponse();
	do {
		unauthenticated = ConnectThroughHttpProxy(
			httpPort,
			destinationPort);
		if (unauthenticated.status || process.state() == QProcess::NotRunning) {
			break;
		}
		QThread::msleep(25);
	} while (startup.elapsed() < kRuntimeTimeout);
	Check(unauthenticated.status == 407,
		"rejected unauthenticated HTTP CONNECT with 407");
	Check(HasBasicProxyChallenge(unauthenticated.headers),
		"advertised Basic authentication for HTTP CONNECT");
	Check(!destination.hasPendingConnections(),
		"did not forward unauthenticated HTTP CONNECT");

	const auto wrong = ConnectThroughHttpProxy(
		httpPort,
		destinationPort,
		"synthetic-wrong-user:synthetic-wrong-password");
	Check(wrong.status == 407,
		"rejected wrong HTTP proxy credentials with 407");
	Check(!destination.hasPendingConnections(),
		"did not forward HTTP CONNECT with wrong credentials");

	const auto valid = ConnectThroughHttpProxy(
		httpPort,
		destinationPort,
		webUser.toUtf8() + ':' + webPassword.toUtf8());
	Check(valid.status == 200,
		"accepted valid HTTP proxy credentials with immediate 200");
	Check(destination.hasPendingConnections()
		|| destination.waitForNewConnection(kProbeTimeout),
		"forwarded authenticated HTTP CONNECT to loopback target");
	while (destination.hasPendingConnections()) {
		destination.nextPendingConnection()->deleteLater();
	}

	Check(process.state() != QProcess::NotRunning,
		"kept Xray alive through HTTP proxy runtime checks");
	Check(StopXray(process),
		"terminated and reaped Xray after HTTP proxy runtime checks");
}

[[nodiscard]] int ValidatePrivateInput() {
	auto input = QByteArray();
	char buffer[1024];
	while (std::cin.good() && input.size() <= 8192) {
		std::cin.read(buffer, sizeof(buffer));
		input.append(buffer, int(std::cin.gcount()));
	}
	while (input.endsWith('\n') || input.endsWith('\r')) {
		input.chop(1);
	}
	if (input.isEmpty() || input.size() > 8192) {
		std::cerr << "VLESS validation failed: invalid input size.\n";
		input.fill('\0');
		return 2;
	}
	const auto text = QString::fromUtf8(input);
	if (text.toUtf8() != input) {
		std::cerr << "VLESS validation failed: invalid UTF-8.\n";
		input.fill('\0');
		return 2;
	}
	input.fill('\0');
	const auto parsed = Core::ParseVlessProfile(text);
	if (!parsed || !parsed.profile) {
		std::cerr << "VLESS validation failed: profile error "
			<< int(parsed.error) << ".\n";
		return 3;
	}
	auto config = parsed.profile->xrayConfig(
		{
			.port = kLocalPort,
			.user = u"validation-user"_q,
			.password = u"validation-password"_q,
		},
		{
			.port = kLocalHttpPort,
			.user = u"validation-web-user"_q,
			.password = u"validation-web-password"_q,
		});
	if (config.isEmpty()) {
		std::cerr << "VLESS validation failed: configuration error.\n";
		return 4;
	}
	const auto accepted = ValidateWithXray(config, "private-input");
	config.fill('\0');
	if (!accepted) {
		return 5;
	}
	std::cout << "VLESS profile accepted.\n";
	return 0;
}

} // namespace

int main(int argc, char *argv[]) {
	const auto application = QCoreApplication(argc, argv);
	if (argc == 2 && QByteArray(argv[1]) == "--validate-stdin") {
		return ValidatePrivateInput();
	} else if (argc != 1) {
		std::cerr << "Unknown test argument.\n";
		return 2;
	}

	CheckRawReality();
	CheckGrpcReality();
	CheckTlsTransports();
	CheckXhttpAndFinalMask();
	CheckEncryptedNoneSecurity();
	CheckRejections();
	CheckCredentialLimits();
	CheckHttpProxyRuntime();

	if (Failures != 0) {
		std::cerr << Failures << " VLESS profile checks failed.\n";
		return 1;
	}
	std::cout << "All VLESS profile checks passed.\n";
	return 0;
}
