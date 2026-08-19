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
#include "rtc_base/socket_factory.h"
#include "rtc_base/thread.h"
#include "rtc_base/time_utils.h"

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace rtc {

int Socket::RecvFrom(ReceiveBuffer &) {
	return -1;
}

} // namespace rtc

namespace {

constexpr auto kExpectedProxyHost = "127.0.0.1";
constexpr auto kExpectedProxyUsername = "synthetic-user";
constexpr auto kExpectedProxyPassword = "synthetic-password";
constexpr auto kExpectedTargetHost = "198.51.100.10";
constexpr auto kExpectedTargetPort = uint16_t(443);
constexpr auto kConnectTimeoutMs = 3000;

struct RouteTrace {
	std::vector<rtc::SocketAddress> binds;
	std::vector<rtc::SocketAddress> connects;
	std::vector<std::pair<rtc::Socket::Option, int>> options;
	int createCalls = 0;
	int createdFamily = AF_UNSPEC;
	int createdType = 0;
	int connectResult = 0;
	int failureError = SOCKET_EACCES;
	bool createSocket = true;
};

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

class RecordingSocket final : public rtc::Socket {
public:
	explicit RecordingSocket(std::shared_ptr<RouteTrace> trace);
	~RecordingSocket() override = default;

	rtc::SocketAddress GetLocalAddress() const override;
	rtc::SocketAddress GetRemoteAddress() const override;
	int Bind(const rtc::SocketAddress &address) override;
	int Connect(const rtc::SocketAddress &address) override;
	int Send(const void *data, size_t size) override;
	int SendTo(
		const void *data,
		size_t size,
		const rtc::SocketAddress &address) override;
	int Recv(void *data, size_t size, int64_t *timestamp) override;
	int RecvFrom(
		void *data,
		size_t size,
		rtc::SocketAddress *address,
		int64_t *timestamp) override;
	int RecvFrom(ReceiveBuffer &buffer) override;
	int Listen(int backlog) override;
	rtc::Socket *Accept(rtc::SocketAddress *address) override;
	int Close() override;
	int GetError() const override;
	void SetError(int error) override;
	ConnState GetState() const override;
	int GetOption(Option option, int *value) override;
	int SetOption(Option option, int value) override;

private:
	std::shared_ptr<RouteTrace> _trace;
	rtc::SocketAddress _localAddress;
	rtc::SocketAddress _remoteAddress;
	ConnState _state = CS_CLOSED;
	int _error = 0;

};

class RecordingSocketFactory final : public rtc::SocketFactory {
public:
	explicit RecordingSocketFactory(std::shared_ptr<RouteTrace> trace);

	rtc::Socket *CreateSocket(int family, int type) override;

private:
	std::shared_ptr<RouteTrace> _trace;

};

static_assert(!std::is_abstract_v<RecordingSocket>);

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

RecordingSocket::RecordingSocket(std::shared_ptr<RouteTrace> trace)
: _trace(std::move(trace)) {
}

rtc::SocketAddress RecordingSocket::GetLocalAddress() const {
	return _localAddress;
}

rtc::SocketAddress RecordingSocket::GetRemoteAddress() const {
	return _remoteAddress;
}

int RecordingSocket::Bind(const rtc::SocketAddress &address) {
	_trace->binds.push_back(address);
	_localAddress = address;
	return 0;
}

int RecordingSocket::Connect(const rtc::SocketAddress &address) {
	_trace->connects.push_back(address);
	if (_trace->connectResult < 0) {
		_error = _trace->failureError;
		return -1;
	}
	_remoteAddress = address;
	_state = CS_CONNECTING;
	return 0;
}

int RecordingSocket::Send(const void *, size_t size) {
	return static_cast<int>(size);
}

int RecordingSocket::SendTo(
		const void *,
		size_t,
		const rtc::SocketAddress &) {
	_error = SOCKET_EACCES;
	return -1;
}

int RecordingSocket::Recv(void *, size_t, int64_t *) {
	_error = EWOULDBLOCK;
	return -1;
}

int RecordingSocket::RecvFrom(
		void *,
		size_t,
		rtc::SocketAddress *,
		int64_t *) {
	_error = EWOULDBLOCK;
	return -1;
}

int RecordingSocket::RecvFrom(ReceiveBuffer &) {
	_error = EWOULDBLOCK;
	return -1;
}

int RecordingSocket::Listen(int) {
	_error = SOCKET_EACCES;
	return -1;
}

rtc::Socket *RecordingSocket::Accept(rtc::SocketAddress *) {
	_error = SOCKET_EACCES;
	return nullptr;
}

int RecordingSocket::Close() {
	_state = CS_CLOSED;
	return 0;
}

int RecordingSocket::GetError() const {
	return _error;
}

void RecordingSocket::SetError(int error) {
	_error = error;
}

rtc::Socket::ConnState RecordingSocket::GetState() const {
	return _state;
}

int RecordingSocket::GetOption(Option, int *value) {
	if (value) {
		*value = 0;
	}
	return 0;
}

int RecordingSocket::SetOption(Option option, int value) {
	_trace->options.emplace_back(option, value);
	return 0;
}

RecordingSocketFactory::RecordingSocketFactory(
	std::shared_ptr<RouteTrace> trace)
: _trace(std::move(trace)) {
}

rtc::Socket *RecordingSocketFactory::CreateSocket(int family, int type) {
	++_trace->createCalls;
	_trace->createdFamily = family;
	_trace->createdType = type;
	return _trace->createSocket
		? new RecordingSocket(_trace)
		: nullptr;
}

[[nodiscard]] bool Expect(bool condition, const char *message) {
	if (!condition) {
		std::cerr << message << '\n';
	}
	return condition;
}

[[nodiscard]] rtc::ProxyInfo AuthenticatedProxy(
		const rtc::SocketAddress &address) {
	auto result = rtc::ProxyInfo();
	result.type = rtc::PROXY_SOCKS5;
	result.address = address;
	result.username = kExpectedProxyUsername;
	const auto password = SyntheticCryptString(kExpectedProxyPassword);
	result.password = rtc::CryptString(password);
	return result;
}

[[nodiscard]] bool TestProxiedRouteUsesOnlyProxy() {
	const auto local = rtc::SocketAddress("192.0.2.20", 0);
	const auto remote = rtc::SocketAddress(
		kExpectedTargetHost,
		kExpectedTargetPort);
	const auto proxyAddress = rtc::SocketAddress(kExpectedProxyHost, 10808);
	const auto proxy = AuthenticatedProxy(proxyAddress);
	const auto trace = std::make_shared<RouteTrace>();
	auto factory = RecordingSocketFactory(trace);
	auto socket = std::unique_ptr<rtc::AsyncPacketSocket>(
		tgcalls::CreateRawTcpSocket(&factory, local, remote, proxy));
	return Expect(socket != nullptr, "route: proxied socket was not created")
		&& Expect(
			trace->createCalls == 1
				&& trace->createdFamily == AF_INET
				&& trace->createdType == SOCK_STREAM,
			"route: wrong transport socket was created")
		&& Expect(
			trace->binds.size() == 1
				&& trace->binds.front().IsAnyIP()
				&& trace->binds.front().port() == 0,
			"route: proxied transport was not wildcard-bound")
		&& Expect(
			trace->connects == std::vector<rtc::SocketAddress>{ proxyAddress },
			"route: transport connected anywhere except the proxy")
		&& Expect(
			std::find(
				trace->options.begin(),
				trace->options.end(),
				std::pair{ rtc::Socket::OPT_NODELAY, 1 })
				!= trace->options.end(),
			"route: TCP_NODELAY was not requested")
		&& Expect(
			socket->GetRemoteAddress() == remote,
			"route: logical destination was not preserved");
}

[[nodiscard]] bool TestProxyFailureHasNoDirectFallback() {
	const auto local = rtc::SocketAddress("192.0.2.20", 0);
	const auto remote = rtc::SocketAddress(
		kExpectedTargetHost,
		kExpectedTargetPort);
	const auto proxyAddress = rtc::SocketAddress(kExpectedProxyHost, 10808);
	const auto proxy = AuthenticatedProxy(proxyAddress);

	const auto connectTrace = std::make_shared<RouteTrace>();
	connectTrace->connectResult = -1;
	auto connectFactory = RecordingSocketFactory(connectTrace);
	auto connectResult = std::unique_ptr<rtc::AsyncPacketSocket>(
		tgcalls::CreateRawTcpSocket(
			&connectFactory,
			local,
			remote,
			proxy));
	if (!Expect(
			!connectResult
				&& connectTrace->createCalls == 1
				&& connectTrace->connects
					== std::vector<rtc::SocketAddress>{ proxyAddress },
			"route: proxy connect failure attempted a direct fallback")) {
		return false;
	}

	const auto createTrace = std::make_shared<RouteTrace>();
	createTrace->createSocket = false;
	auto createFactory = RecordingSocketFactory(createTrace);
	auto createResult = std::unique_ptr<rtc::AsyncPacketSocket>(
		tgcalls::CreateRawTcpSocket(
			&createFactory,
			local,
			remote,
			proxy));
	return Expect(
		!createResult
			&& createTrace->createCalls == 1
			&& createTrace->connects.empty(),
		"route: proxy socket creation failure attempted a fallback");
}

[[nodiscard]] bool TestInvalidPolicyCreatesNoSocket() {
	const auto local = rtc::SocketAddress("192.0.2.20", 0);
	const auto remote = rtc::SocketAddress(
		kExpectedTargetHost,
		kExpectedTargetPort);
	const auto valid = AuthenticatedProxy(
		rtc::SocketAddress(kExpectedProxyHost, 10808));
	const auto rejected = [&](
			const rtc::ProxyInfo &proxy,
			const rtc::SocketAddress &target) {
		const auto trace = std::make_shared<RouteTrace>();
		auto factory = RecordingSocketFactory(trace);
		auto socket = std::unique_ptr<rtc::AsyncPacketSocket>(
			tgcalls::CreateRawTcpSocket(&factory, local, target, proxy));
		return !socket
			&& trace->createCalls == 0
			&& trace->binds.empty()
			&& trace->connects.empty();
	};

	auto unsupported = valid;
	unsupported.type = rtc::PROXY_HTTPS;
	auto noUsername = valid;
	noUsername.username.clear();
	auto noPassword = valid;
	noPassword.password.Clear();
	auto longUsername = valid;
	longUsername.username.assign(256, 'u');
	auto longPassword = valid;
	const auto longPasswordValue = SyntheticCryptString(std::string(256, 'p'));
	longPassword.password = rtc::CryptString(longPasswordValue);
	auto unresolved = valid;
	unresolved.address = rtc::SocketAddress("proxy.invalid", 10808);
	auto missingPort = valid;
	missingPort.address.SetPort(0);
	auto portlessTarget = remote;
	portlessTarget.SetPort(0);
	auto scopedTarget = rtc::SocketAddress("2001:db8::1", remote.port());
	scopedTarget.SetScopeID(1);
	return Expect(
		rejected(unsupported, remote),
		"policy: HTTPS proxy was accepted")
		&& Expect(
			rejected(noUsername, remote),
			"policy: empty username was accepted")
		&& Expect(
			rejected(noPassword, remote),
			"policy: empty password was accepted")
		&& Expect(
			rejected(longUsername, remote),
			"policy: overlong username was accepted")
		&& Expect(
			rejected(longPassword, remote),
			"policy: overlong password was accepted")
		&& Expect(
			rejected(unresolved, remote),
			"policy: unresolved proxy was accepted")
		&& Expect(
			rejected(missingPort, remote),
			"policy: portless proxy was accepted")
		&& Expect(
			rejected(valid, portlessTarget),
			"policy: portless target was accepted")
		&& Expect(
			rejected(valid, scopedTarget),
			"policy: scoped IPv6 target was accepted")
		&& Expect(
			tgcalls::CreateRawTcpSocket(nullptr, local, remote, valid) == nullptr,
			"policy: null socket factory was accepted");
}

[[nodiscard]] bool TestDirectRouteRequiresExplicitNoProxy() {
	const auto local = rtc::SocketAddress("192.0.2.20", 0);
	const auto remote = rtc::SocketAddress(
		kExpectedTargetHost,
		kExpectedTargetPort);
	auto direct = rtc::ProxyInfo();
	direct.type = rtc::PROXY_NONE;
	const auto trace = std::make_shared<RouteTrace>();
	auto factory = RecordingSocketFactory(trace);
	auto socket = std::unique_ptr<rtc::AsyncPacketSocket>(
		tgcalls::CreateRawTcpSocket(&factory, local, remote, direct));
	return Expect(socket != nullptr, "route: explicit direct socket was rejected")
		&& Expect(
			trace->binds == std::vector<rtc::SocketAddress>{ local },
			"route: explicit direct socket used the wrong bind address")
		&& Expect(
			trace->connects == std::vector<rtc::SocketAddress>{ remote },
			"route: explicit direct socket used the wrong destination");
}

[[nodiscard]] bool RunPolicyTests() {
	return TestProxiedRouteUsesOnlyProxy()
		&& TestProxyFailureHasNoDirectFallback()
		&& TestInvalidPolicyCreatesNoSocket()
		&& TestDirectRouteRequiresExplicitNoProxy();
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

int main(int argc, char *argv[]) {
	if (argc == 2 && std::string(argv[1]) == "--policy-only") {
		return RunPolicyTests() ? 0 : 1;
	} else if (argc != 1) {
		std::cerr << "Usage: test_call_proxy_route [--policy-only]\n";
		return 2;
	} else if (!RunPolicyTests()) {
		return 1;
	}

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
