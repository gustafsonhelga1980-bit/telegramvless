/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "webview/webview_embed.h"
#include "webview/webview_interface.h"

#include <QtCore/QByteArray>
#include <QtCore/QCoreApplication>
#include <QtCore/QObject>
#include <QtCore/QString>
#include <QtNetwork/QAuthenticator>
#include <QtNetwork/QNetworkProxy>
#include <QtNetwork/QTcpSocket>

#include <array>
#include <charconv>
#include <cstdint>
#include <iostream>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace {

constexpr auto kProxyHost = "127.0.0.1";
constexpr auto kProxyUsername = "synthetic-user";
constexpr auto kProxyPassword = "synthetic-password";
constexpr auto kRouteTimeout = 3000;

struct Route {
	std::string name;
	std::string host;
	std::uint16_t port = 0;
	QByteArray probe;
};

enum class RouteResult {
	Blocked,
	Failed,
	Connected,
};

[[nodiscard]] bool Expect(bool condition, const std::string &message) {
	if (!condition) {
		std::cerr << message << '\n';
	}
	return condition;
}

[[nodiscard]] Webview::NetworkConfig ManagedNetwork() {
	return {
		.mode = Webview::NetworkMode::HttpProxy,
		.proxy = {
			.host = kProxyHost,
			.port = 10809,
			.username = kProxyUsername,
			.password = kProxyPassword,
		},
	};
}

[[nodiscard]] bool Rejected(Webview::NetworkConfig network) {
	auto config = Webview::Config();
	config.network = std::move(network);
	return !Webview::CreateInstance(std::move(config));
}

[[nodiscard]] bool TestFailClosedPolicy() {
	auto result = true;
	const auto defaultNetwork = Webview::NetworkConfig();
	result &= Expect(
		defaultNetwork.mode == Webview::NetworkMode::Denied,
		"webview policy: network default was not denied");
	result &= Expect(
		Webview::Config().network.mode == Webview::NetworkMode::Denied,
		"webview policy: backend config default was not denied");
	result &= Expect(
		Webview::WindowConfig().network.mode == Webview::NetworkMode::Denied,
		"webview policy: window config default was not denied");
	result &= Expect(
		Rejected(defaultNetwork),
		"webview policy: denied config created a backend");

	auto invalid = ManagedNetwork();
	invalid.proxy.host = "198.51.100.1";
	result &= Expect(
		Rejected(std::move(invalid)),
		"webview policy: non-loopback proxy was accepted");

	invalid = ManagedNetwork();
	invalid.proxy.port = 0;
	result &= Expect(
		Rejected(std::move(invalid)),
		"webview policy: zero proxy port was accepted");

	invalid = ManagedNetwork();
	invalid.proxy.username.clear();
	result &= Expect(
		Rejected(std::move(invalid)),
		"webview policy: empty proxy username was accepted");

	invalid = ManagedNetwork();
	invalid.proxy.password.clear();
	result &= Expect(
		Rejected(std::move(invalid)),
		"webview policy: empty proxy password was accepted");

	invalid = ManagedNetwork();
	invalid.proxy.username.assign(256, 'u');
	result &= Expect(
		Rejected(std::move(invalid)),
		"webview policy: oversized proxy username was accepted");

	invalid = ManagedNetwork();
	invalid.proxy.password.assign(256, 'p');
	result &= Expect(
		Rejected(std::move(invalid)),
		"webview policy: oversized proxy password was accepted");

	invalid = ManagedNetwork();
	invalid.proxy.username = std::string("user\0suffix", 11);
	result &= Expect(
		Rejected(std::move(invalid)),
		"webview policy: proxy username with NUL was accepted");

	invalid = ManagedNetwork();
	invalid.proxy.password = std::string("pass\0suffix", 11);
	result &= Expect(
		Rejected(std::move(invalid)),
		"webview policy: proxy password with NUL was accepted");
	return result;
}

[[nodiscard]] std::optional<std::uint16_t> ParsePort(
		const QByteArray &value) {
	if (value.isEmpty()) {
		return std::nullopt;
	}
	auto parsed = std::uint32_t();
	const auto begin = value.constData();
	const auto end = begin + value.size();
	const auto result = std::from_chars(begin, end, parsed);
	if (result.ec != std::errc()
		|| result.ptr != end
		|| !parsed
		|| parsed > std::numeric_limits<std::uint16_t>::max()) {
		return std::nullopt;
	}
	return static_cast<std::uint16_t>(parsed);
}

[[nodiscard]] std::optional<Route> ReadRoute(std::string_view name) {
	const auto prefix = QByteArray("NO_DIRECT_EGRESS_WEBVIEW_")
		+ QByteArray(name.data(), static_cast<int>(name.size()));
	const auto hostName = prefix + "_HOST";
	const auto portName = prefix + "_PORT";
	const auto probeName = prefix + "_PROBE";
	const auto host = qgetenv(hostName.constData());
	const auto port = ParsePort(qgetenv(portName.constData()));
	const auto probe = qgetenv(probeName.constData());
	if (host.isEmpty() || !port || probe.isEmpty()) {
		return std::nullopt;
	}
	return Route{
		.name = std::string(name),
		.host = host.toStdString(),
		.port = *port,
		.probe = probe,
	};
}

[[nodiscard]] bool ValidManagedNetwork(
		const Webview::NetworkConfig &network) {
	const auto validCredential = [](const std::string &value) {
		return !value.empty()
			&& value.size() <= 255
			&& value.find('\0') == std::string::npos;
	};
	return network.mode == Webview::NetworkMode::HttpProxy
		&& network.proxy.host == kProxyHost
		&& network.proxy.port
		&& validCredential(network.proxy.username)
		&& validCredential(network.proxy.password);
}

[[nodiscard]] RouteResult ConnectRoute(
		const Webview::NetworkConfig &network,
		const Route &route) {
	if (network.mode == Webview::NetworkMode::Denied) {
		return RouteResult::Blocked;
	} else if (!ValidManagedNetwork(network)) {
		return RouteResult::Failed;
	}
	auto socket = QTcpSocket();
	const auto proxy = QNetworkProxy(
		QNetworkProxy::HttpProxy,
		QString::fromStdString(network.proxy.host),
		network.proxy.port,
		QString::fromStdString(network.proxy.username),
		QString::fromStdString(network.proxy.password));
	socket.setProxy(proxy);
	auto authenticationRequests = 0;
	QObject::connect(
		&socket,
		&QAbstractSocket::proxyAuthenticationRequired,
		&socket,
		[&](const QNetworkProxy &requested, QAuthenticator *authenticator) {
			++authenticationRequests;
			if (authenticationRequests == 1
				&& requested.hostName() == proxy.hostName()
				&& requested.port() == proxy.port()) {
				authenticator->setUser(proxy.user());
				authenticator->setPassword(proxy.password());
			}
		});
	socket.connectToHost(QString::fromStdString(route.host), route.port);
	if (!socket.waitForConnected(kRouteTimeout)) {
		std::cerr << "webview route: " << route.name
			<< " connect failed: "
			<< socket.errorString().toStdString()
			<< " (auth=" << authenticationRequests << ")\n";
		return RouteResult::Failed;
	}
	if (socket.write(route.probe) != route.probe.size()
		|| (socket.bytesToWrite()
			&& !socket.waitForBytesWritten(kRouteTimeout))
		|| (!socket.bytesAvailable()
			&& !socket.waitForReadyRead(kRouteTimeout))
		|| socket.readAll() != QByteArray(1, '\0')) {
		return RouteResult::Failed;
	}
	socket.close();
	return RouteResult::Connected;
}

[[nodiscard]] bool TestLiveRoute() {
	if (qgetenv("NO_DIRECT_EGRESS_PROXY_PROTOCOL") != "http") {
		return Expect(false, "webview route: expected an HTTP proxy fixture");
	}
	const auto proxyPort = ParsePort(qgetenv("NO_DIRECT_EGRESS_PROXY_PORT"));
	if (!proxyPort) {
		return Expect(false, "webview route: invalid proxy port");
	}
	auto network = Webview::NetworkConfig{
		.mode = Webview::NetworkMode::HttpProxy,
		.proxy = {
			.host = qgetenv("NO_DIRECT_EGRESS_PROXY_HOST").toStdString(),
			.port = *proxyPort,
			.username = qgetenv(
				"NO_DIRECT_EGRESS_PROXY_USERNAME").toStdString(),
			.password = qgetenv(
				"NO_DIRECT_EGRESS_PROXY_PASSWORD").toStdString(),
		},
	};
	const auto names = std::array{
		std::string_view("NAVIGATION"),
		std::string_view("REDIRECT"),
		std::string_view("SUBRESOURCE"),
		std::string_view("WEBSOCKET"),
	};
	for (const auto name : names) {
		const auto route = ReadRoute(name);
		if (!route) {
			return Expect(false, "webview route: incomplete route fixture");
		} else if (ConnectRoute(network, *route) != RouteResult::Connected) {
			return Expect(
				false,
				"webview route: managed " + route->name + " failed");
		}
	}
	network = Webview::NetworkConfig();
	return Expect(
		ConnectRoute(
			network,
			Route{
				.name = "after-teardown",
				.host = "198.51.100.14",
				.port = 443,
				.probe = "synthetic-webview-after-teardown-probe",
			}) == RouteResult::Blocked,
		"webview route: denied mode attempted a post-teardown route");
}

} // namespace

int main(int argc, char *argv[]) {
	[[maybe_unused]] const auto application = QCoreApplication(argc, argv);
	if (argc == 2 && std::string_view(argv[1]) == "--live-route") {
		return TestLiveRoute() ? 0 : 1;
	} else if (argc == 1
			|| (argc == 2
				&& std::string_view(argv[1]) == "--policy-only")) {
		return TestFailClosedPolicy() ? 0 : 1;
	}
	std::cerr << "usage: test_webview_proxy_route "
		"[--policy-only|--live-route]\n";
	return 2;
}
