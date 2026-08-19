/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "v2/RawTcpSocketFactory.h"

#include "rtc_base/async_packet_socket.h"
#include "rtc_base/crypt_string.h"
#include "rtc_base/ip_address.h"
#include "rtc_base/physical_socket_server.h"
#include "rtc_base/thread.h"
#include "rtc_base/time_utils.h"

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace {

constexpr auto kExpectedProxyHost = "127.0.0.1";
constexpr auto kExpectedProxyUsername = "synthetic-user";
constexpr auto kExpectedProxyPassword = "synthetic-password";
constexpr auto kExpectedTargetHost = "198.51.100.10";
constexpr auto kExpectedTargetPort = uint16_t(443);
constexpr auto kConnectTimeoutMs = 3000;

class SyntheticCryptString final : public rtc::CryptStringImpl {
public:
	explicit SyntheticCryptString(std::string value);

	size_t GetLength() const override;
	void CopyTo(char *destination, bool nullTerminate) const override;
	std::string UrlEncode() const override;
	rtc::CryptStringImpl *Copy() const override;
	void CopyRawTo(std::vector<unsigned char> *destination) const override;

private:
	std::string _value;

};

class SocketObserver final : public sigslot::has_slots<> {
public:
	void connected(rtc::AsyncPacketSocket *);

	bool isConnected = false;
	bool isClosed = false;

};

SyntheticCryptString::SyntheticCryptString(std::string value)
: _value(std::move(value)) {
}

size_t SyntheticCryptString::GetLength() const {
	return _value.size();
}

void SyntheticCryptString::CopyTo(char *destination, bool nullTerminate) const {
	std::copy(_value.begin(), _value.end(), destination);
	if (nullTerminate) {
		destination[_value.size()] = 0;
	}
}

std::string SyntheticCryptString::UrlEncode() const {
	return _value;
}

rtc::CryptStringImpl *SyntheticCryptString::Copy() const {
	return new SyntheticCryptString(_value);
}

void SyntheticCryptString::CopyRawTo(
		std::vector<unsigned char> *destination) const {
	destination->assign(_value.begin(), _value.end());
}

void SocketObserver::connected(rtc::AsyncPacketSocket *) {
	isConnected = true;
}

[[nodiscard]] const char *RequiredEnvironment(const char *name) {
	const auto value = std::getenv(name);
	if (!value || !*value) {
		std::cerr << "Missing required synthetic environment: " << name << '\n';
		return nullptr;
	}
	return value;
}

[[nodiscard]] bool ParsePort(const char *text, uint16_t &port) {
	auto parsed = unsigned();
	const auto end = text + std::char_traits<char>::length(text);
	const auto result = std::from_chars(text, end, parsed);
	if (result.ec != std::errc()
		|| result.ptr != end
		|| parsed == 0
		|| parsed > 65535) {
		return false;
	}
	port = uint16_t(parsed);
	return true;
}

[[nodiscard]] bool RejectsInvalidInputs(
		rtc::SocketFactory *factory,
		const rtc::SocketAddress &local,
		const rtc::SocketAddress &remote,
		const rtc::ProxyInfo &valid) {
	const auto rejected = [&](
			const rtc::ProxyInfo &proxy,
			const rtc::SocketAddress &target) {
		auto socket = std::unique_ptr<rtc::AsyncPacketSocket>(
			tgcalls::CreateRawTcpSocket(factory, local, target, proxy));
		if (socket) {
			socket->Close();
			return false;
		}
		return true;
	};

	auto unsupported = valid;
	unsupported.type = rtc::PROXY_HTTPS;
	if (!rejected(unsupported, remote)) {
		return false;
	}
	auto unauthenticated = valid;
	unauthenticated.password.Clear();
	if (!rejected(unauthenticated, remote)) {
		return false;
	}
	auto unresolved = valid;
	unresolved.address = rtc::SocketAddress(
		"synthetic-proxy.invalid",
		valid.address.port());
	if (!rejected(unresolved, remote)) {
		return false;
	}
	auto missingPort = remote;
	missingPort.SetPort(0);
	if (!rejected(valid, missingPort)) {
		return false;
	}
	auto scopedIpv6 = rtc::SocketAddress("2001:db8::1", remote.port());
	scopedIpv6.SetScopeID(1);
	return rejected(valid, scopedIpv6);
}

} // namespace

int main() {
	const auto proxyHost = RequiredEnvironment("NO_DIRECT_EGRESS_PROXY_HOST");
	const auto proxyPortText = RequiredEnvironment("NO_DIRECT_EGRESS_PROXY_PORT");
	const auto proxyUsername = RequiredEnvironment(
		"NO_DIRECT_EGRESS_PROXY_USERNAME");
	const auto proxyPassword = RequiredEnvironment(
		"NO_DIRECT_EGRESS_PROXY_PASSWORD");
	const auto targetHost = RequiredEnvironment("NO_DIRECT_EGRESS_TARGET_HOST");
	const auto targetPortText = RequiredEnvironment(
		"NO_DIRECT_EGRESS_TARGET_PORT");
	if (!proxyHost
		|| !proxyPortText
		|| !proxyUsername
		|| !proxyPassword
		|| !targetHost
		|| !targetPortText) {
		return 2;
	}

	auto proxyPort = uint16_t();
	auto targetPort = uint16_t();
	if (std::string(proxyHost) != kExpectedProxyHost
		|| std::string(proxyUsername) != kExpectedProxyUsername
		|| std::string(proxyPassword) != kExpectedProxyPassword
		|| std::string(targetHost) != kExpectedTargetHost
		|| !ParsePort(proxyPortText, proxyPort)
		|| !ParsePort(targetPortText, targetPort)
		|| targetPort != kExpectedTargetPort) {
		std::cerr << "Refusing non-synthetic call proxy test input.\n";
		return 2;
	}

	auto socketServer = rtc::PhysicalSocketServer();
	auto thread = rtc::AutoSocketServerThread(&socketServer);
	const auto local = rtc::SocketAddress(rtc::GetAnyIP(AF_INET), 0);
	const auto remote = rtc::SocketAddress(targetHost, targetPort);
	auto proxy = rtc::ProxyInfo();
	proxy.type = rtc::PROXY_SOCKS5;
	proxy.address = rtc::SocketAddress(proxyHost, proxyPort);
	proxy.username = proxyUsername;
	const auto password = SyntheticCryptString(proxyPassword);
	proxy.password = rtc::CryptString(password);

	if (proxy.address.IsUnresolvedIP()
		|| !proxy.address.IsLoopbackIP()
		|| remote.IsUnresolvedIP()
		|| !RejectsInvalidInputs(&socketServer, local, remote, proxy)) {
		std::cerr << "Synthetic call proxy validation failed.\n";
		return 3;
	}

	auto socket = std::unique_ptr<rtc::AsyncPacketSocket>(
		tgcalls::CreateRawTcpSocket(
			&socketServer,
			local,
			remote,
			proxy));
	if (!socket) {
		std::cerr << "Could not create the synthetic proxied socket.\n";
		return 4;
	}

	auto observer = SocketObserver();
	socket->SignalConnect.connect(&observer, &SocketObserver::connected);
	socket->SubscribeCloseEvent(
		&observer,
		[&](rtc::AsyncPacketSocket *, int) { observer.isClosed = true; });
	observer.isConnected = (socket->GetState()
		== rtc::AsyncPacketSocket::STATE_CONNECTED);
	const auto deadline = rtc::TimeMillis() + kConnectTimeoutMs;
	while (!observer.isConnected && !observer.isClosed) {
		const auto remaining = deadline - rtc::TimeMillis();
		if (remaining <= 0) {
			break;
		}
		thread.ProcessMessages(int(std::min<int64_t>(remaining, 20)));
	}

	socket->SignalConnect.disconnect(&observer);
	socket->UnsubscribeCloseEvent(&observer);
	socket->Close();
	if (!observer.isConnected || observer.isClosed) {
		std::cerr << "Synthetic SOCKS5 CONNECT did not succeed.\n";
		return 5;
	}
	return 0;
}
