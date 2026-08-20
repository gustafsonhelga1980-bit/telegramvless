/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "group/GroupNetworkManager.h"

#include "Instance.h"
#include "api/async_dns_resolver.h"
#include "api/packet_socket_factory.h"
#include "rtc_base/async_packet_socket.h"
#include "rtc_base/buffer.h"
#include "rtc_base/network/received_packet.h"
#include "rtc_base/physical_socket_server.h"
#include "rtc_base/proxy_info.h"
#include "rtc_base/socket_factory.h"
#include "rtc_base/thread.h"
#include "rtc_base/time_utils.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdint>
#include <cstdlib>
#include <cstring>
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

constexpr auto kProxyHost = "127.0.0.1";
constexpr auto kProxyPort = uint16_t(10808);
constexpr auto kUsername = "synthetic-user";
constexpr auto kPassword = "synthetic-password";
constexpr auto kTargetHost = "198.51.100.10";
constexpr auto kTargetPort = uint16_t(443);
constexpr auto kPublicCandidateHost = "8.8.8.8";
constexpr auto kRelayPort = uint16_t(40123);
constexpr auto kMainProbe = "synthetic-group-main-udp-probe";
constexpr auto kMainReply = "synthetic-group-main-udp-reply";
constexpr auto kPresentationProbe =
	"synthetic-group-presentation-udp-probe";
constexpr auto kPresentationReply =
	"synthetic-group-presentation-udp-reply";
constexpr auto kRouteTimeoutMs = 3000;

struct SocketTrace {
	std::vector<rtc::SocketAddress> binds;
	std::vector<rtc::SocketAddress> connects;
	std::vector<std::pair<rtc::Socket::Option, int>> options;
	std::vector<uint8_t> sent;
	int addressedSends = 0;
	int closeCalls = 0;
};

class ScriptedSocket final : public rtc::Socket {
public:
	ScriptedSocket(
		std::shared_ptr<SocketTrace> trace,
		bool connectFails);
	~ScriptedSocket() override = default;

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

	void CompleteConnect();
	void Receive(std::vector<uint8_t> bytes);

private:
	std::shared_ptr<SocketTrace> _trace;
	rtc::SocketAddress _localAddress;
	rtc::SocketAddress _remoteAddress;
	std::vector<uint8_t> _input;
	ConnState _state = CS_CLOSED;
	int _error = 0;
	bool _connectFails = false;

};

class ScriptedSocketFactory final : public rtc::SocketFactory {
public:
	rtc::Socket *CreateSocket(int family, int type) override;

	std::vector<std::pair<int, int>> creates;
	std::shared_ptr<SocketTrace> tcpTrace = std::make_shared<SocketTrace>();
	std::shared_ptr<SocketTrace> udpTrace = std::make_shared<SocketTrace>();
	ScriptedSocket *tcp = nullptr;
	ScriptedSocket *udp = nullptr;
	bool createTcp = true;
	bool createUdp = true;
	bool tcpConnectFails = false;

};

static_assert(!std::is_abstract_v<ScriptedSocket>);

ScriptedSocket::ScriptedSocket(
	std::shared_ptr<SocketTrace> trace,
	bool connectFails)
: _trace(std::move(trace))
, _connectFails(connectFails) {
}

rtc::SocketAddress ScriptedSocket::GetLocalAddress() const {
	return _localAddress;
}

rtc::SocketAddress ScriptedSocket::GetRemoteAddress() const {
	return _remoteAddress;
}

int ScriptedSocket::Bind(const rtc::SocketAddress &address) {
	_trace->binds.push_back(address);
	_localAddress = address;
	return 0;
}

int ScriptedSocket::Connect(const rtc::SocketAddress &address) {
	_trace->connects.push_back(address);
	_remoteAddress = address;
	if (_connectFails) {
		_error = ECONNREFUSED;
		return -1;
	}
	_state = CS_CONNECTING;
	return 0;
}

int ScriptedSocket::Send(const void *data, size_t size) {
	const auto bytes = static_cast<const uint8_t*>(data);
	_trace->sent.insert(_trace->sent.end(), bytes, bytes + size);
	_error = 0;
	return static_cast<int>(size);
}

int ScriptedSocket::SendTo(
		const void *,
		size_t,
		const rtc::SocketAddress &) {
	++_trace->addressedSends;
	_error = SOCKET_EACCES;
	return -1;
}

int ScriptedSocket::Recv(
		void *data,
		size_t size,
		int64_t *timestamp) {
	if (_input.empty()) {
		_error = EWOULDBLOCK;
		return -1;
	}
	const auto count = std::min(size, _input.size());
	std::memcpy(data, _input.data(), count);
	_input.erase(_input.begin(), _input.begin() + count);
	if (timestamp) {
		*timestamp = 0;
	}
	_error = 0;
	return static_cast<int>(count);
}

int ScriptedSocket::RecvFrom(
		void *data,
		size_t size,
		rtc::SocketAddress *address,
		int64_t *timestamp) {
	const auto result = Recv(data, size, timestamp);
	if (result >= 0 && address) {
		*address = _remoteAddress;
	}
	return result;
}

int ScriptedSocket::RecvFrom(ReceiveBuffer &buffer) {
	if (_input.empty()) {
		_error = EWOULDBLOCK;
		return -1;
	}
	buffer.payload.SetData(_input.data(), _input.size());
	buffer.source_address = _remoteAddress;
	const auto result = static_cast<int>(_input.size());
	_input.clear();
	_error = 0;
	return result;
}

int ScriptedSocket::Listen(int) {
	_error = SOCKET_EACCES;
	return -1;
}

rtc::Socket *ScriptedSocket::Accept(rtc::SocketAddress *) {
	_error = SOCKET_EACCES;
	return nullptr;
}

int ScriptedSocket::Close() {
	++_trace->closeCalls;
	_state = CS_CLOSED;
	return 0;
}

int ScriptedSocket::GetError() const {
	return _error;
}

void ScriptedSocket::SetError(int error) {
	_error = error;
}

rtc::Socket::ConnState ScriptedSocket::GetState() const {
	return _state;
}

int ScriptedSocket::GetOption(Option, int *value) {
	if (value) {
		*value = 0;
	}
	return 0;
}

int ScriptedSocket::SetOption(Option option, int value) {
	_trace->options.emplace_back(option, value);
	return 0;
}

void ScriptedSocket::CompleteConnect() {
	_state = CS_CONNECTED;
	_error = 0;
	SignalConnectEvent(this);
}

void ScriptedSocket::Receive(std::vector<uint8_t> bytes) {
	_input.insert(_input.end(), bytes.begin(), bytes.end());
	SignalReadEvent(this);
}

rtc::Socket *ScriptedSocketFactory::CreateSocket(int family, int type) {
	creates.emplace_back(family, type);
	if ((type == SOCK_DGRAM && !createUdp)
		|| (type == SOCK_STREAM && !createTcp)) {
		return nullptr;
	}
	if (type == SOCK_DGRAM && !udp) {
		auto result = std::make_unique<ScriptedSocket>(udpTrace, false);
		udp = result.get();
		return result.release();
	} else if (type == SOCK_STREAM && !tcp) {
		auto result = std::make_unique<ScriptedSocket>(
			tcpTrace,
			tcpConnectFails);
		tcp = result.get();
		return result.release();
	}
	return nullptr;
}

[[nodiscard]] bool Expect(bool condition, const std::string &message) {
	if (!condition) {
		std::cerr << message << '\n';
	}
	return condition;
}

[[nodiscard]] tgcalls::Proxy ValidProxy(uint16_t port = kProxyPort) {
	auto result = tgcalls::Proxy();
	result.host = kProxyHost;
	result.port = port;
	result.managed = true;
	result.login = kUsername;
	result.password = kPassword;
	return result;
}

[[nodiscard]] std::vector<uint8_t> Greeting() {
	return { 5, 1, 2 };
}

[[nodiscard]] std::vector<uint8_t> GreetingAndAuthentication() {
	auto result = Greeting();
	result.push_back(1);
	result.push_back(uint8_t(std::strlen(kUsername)));
	result.insert(result.end(), kUsername, kUsername + std::strlen(kUsername));
	result.push_back(uint8_t(std::strlen(kPassword)));
	result.insert(result.end(), kPassword, kPassword + std::strlen(kPassword));
	return result;
}

[[nodiscard]] std::vector<uint8_t> CompleteControlRequest() {
	auto result = GreetingAndAuthentication();
	const auto associate = std::array<uint8_t, 10>{
		5,
		3,
		0,
		1,
		0,
		0,
		0,
		0,
		0,
		0,
	};
	result.insert(result.end(), associate.begin(), associate.end());
	return result;
}

[[nodiscard]] std::vector<uint8_t> AssociateResponse(
		const std::array<uint8_t, 4> &address,
		uint16_t port) {
	return {
		5,
		0,
		0,
		1,
		address[0],
		address[1],
		address[2],
		address[3],
		uint8_t(port >> 8),
		uint8_t(port),
	};
}

[[nodiscard]] bool AdvanceToAssociate(
		ScriptedSocketFactory &raw,
		int &failures) {
	if (!raw.tcp || !raw.udp) {
		return false;
	}
	raw.tcp->CompleteConnect();
	if (raw.tcpTrace->sent != Greeting() || failures) {
		return false;
	}
	raw.tcp->Receive({ 5, 2 });
	if (raw.tcpTrace->sent != GreetingAndAuthentication() || failures) {
		return false;
	}
	raw.tcp->Receive({ 1, 0 });
	return raw.tcpTrace->sent == CompleteControlRequest() && !failures;
}

[[nodiscard]] bool TestRoleUsesManagedUdp(const std::string &role) {
	auto raw = ScriptedSocketFactory();
	auto failures = 0;
	const auto proxy = ValidProxy();
	auto factory = tgcalls::CreateGroupPacketSocketFactory(
		&raw,
		&proxy,
		[&] { ++failures; });
	auto socket = std::unique_ptr<rtc::AsyncPacketSocket>(
		factory->CreateUdpSocket(
			rtc::SocketAddress(rtc::GetAnyIP(AF_INET), 0),
			0,
			0));
	auto noProxy = rtc::ProxyInfo();
	auto tcpOptions = rtc::PacketSocketTcpOptions();
	auto dns = factory->CreateAsyncDnsResolver();
	const auto result = Expect(
		socket != nullptr,
		role + ": managed UDP socket was not created")
		&& Expect(
			raw.creates == std::vector<std::pair<int, int>>{
				{ AF_INET, SOCK_DGRAM },
				{ AF_INET, SOCK_STREAM },
			},
			role + ": raw socket types were not SOCKS UDP and control TCP")
		&& Expect(
			raw.tcpTrace->connects
				== std::vector<rtc::SocketAddress>{
					rtc::SocketAddress(kProxyHost, kProxyPort),
				},
			role + ": control socket connected anywhere except the proxy")
		&& Expect(
			raw.tcpTrace->binds
				== std::vector<rtc::SocketAddress>{
					rtc::SocketAddress(kProxyHost, 0),
				}
				&& raw.udpTrace->binds
					== std::vector<rtc::SocketAddress>{
						rtc::SocketAddress(kProxyHost, 0),
					},
			role + ": raw sockets were not loopback-bound")
		&& Expect(
			std::find(
				raw.tcpTrace->options.begin(),
				raw.tcpTrace->options.end(),
				std::pair{ rtc::Socket::OPT_NODELAY, 1 })
				!= raw.tcpTrace->options.end(),
			role + ": control socket did not request TCP_NODELAY")
		&& Expect(
			raw.udpTrace->connects.empty(),
			role + ": UDP socket connected before relay negotiation")
		&& Expect(
			factory->CreateServerTcpSocket(
				rtc::SocketAddress(rtc::GetAnyIP(AF_INET), 0),
				0,
				0,
				0) == nullptr,
			role + ": managed route exposed a TCP listener")
		&& Expect(
			factory->CreateClientTcpSocket(
				rtc::SocketAddress(rtc::GetAnyIP(AF_INET), 0),
				rtc::SocketAddress(kTargetHost, kTargetPort),
				noProxy,
				std::string(),
				tcpOptions) == nullptr,
			role + ": managed route exposed direct client TCP")
		&& Expect(
			!dns,
			role + ": managed route exposed direct async DNS")
		&& Expect(
			raw.creates == std::vector<std::pair<int, int>>{
				{ AF_INET, SOCK_DGRAM },
				{ AF_INET, SOCK_STREAM },
			},
			role + ": denied transports reached the raw socket factory")
		&& Expect(
			!raw.tcpTrace->addressedSends
				&& !raw.udpTrace->addressedSends,
			role + ": raw socket made an addressed send")
		&& Expect(!failures, role + ": route failed before negotiation");
	socket.reset();
	return result && Expect(
		!failures,
		role + ": clean socket destruction reported a route failure");
}

[[nodiscard]] bool TestMainAndPresentationUseManagedUdp() {
	return TestRoleUsesManagedUdp("main")
		&& TestRoleUsesManagedUdp("presentation");
}

[[nodiscard]] bool TestUnmanagedRouteUsesStandardFactory() {
	auto raw = ScriptedSocketFactory();
	auto failures = 0;
	auto proxy = ValidProxy();
	proxy.managed = false;
	auto factory = tgcalls::CreateGroupPacketSocketFactory(
		&raw,
		&proxy,
		[&] { ++failures; });
	const auto local = rtc::SocketAddress(rtc::GetAnyIP(AF_INET), 0);
	auto socket = std::unique_ptr<rtc::AsyncPacketSocket>(
		factory->CreateUdpSocket(local, 0, 0));
	return Expect(socket != nullptr, "unmanaged: standard UDP was rejected")
		&& Expect(
			raw.creates == std::vector<std::pair<int, int>>{
				{ AF_INET, SOCK_DGRAM },
			},
			"unmanaged: standard factory created the wrong transport")
		&& Expect(
			raw.udpTrace->binds
				== std::vector<rtc::SocketAddress>{ local },
			"unmanaged: standard factory used the wrong bind")
		&& Expect(!failures, "unmanaged: managed failure callback fired");
}

[[nodiscard]] bool TestInvalidManagedPolicyCreatesNoSocket() {
	auto cases = std::vector<std::pair<std::string, tgcalls::Proxy>>();
	const auto add = [&](std::string name, tgcalls::Proxy proxy) {
		cases.emplace_back(std::move(name), std::move(proxy));
	};
	auto emptyHost = ValidProxy();
	emptyHost.host.clear();
	add("empty host", std::move(emptyHost));
	auto unresolved = ValidProxy();
	unresolved.host = "proxy.invalid";
	add("unresolved host", std::move(unresolved));
	auto nonLoopback = ValidProxy();
	nonLoopback.host = kTargetHost;
	add("non-loopback host", std::move(nonLoopback));
	auto missingPort = ValidProxy();
	missingPort.port = 0;
	add("missing port", std::move(missingPort));
	auto noLogin = ValidProxy();
	noLogin.login.clear();
	add("empty username", std::move(noLogin));
	auto noPassword = ValidProxy();
	noPassword.password.clear();
	add("empty password", std::move(noPassword));
	auto longLogin = ValidProxy();
	longLogin.login.assign(256, 'u');
	add("overlong username", std::move(longLogin));
	auto longPassword = ValidProxy();
	longPassword.password.assign(256, 'p');
	add("overlong password", std::move(longPassword));
	auto nulLogin = ValidProxy();
	nulLogin.login = std::string("user\0name", 9);
	add("NUL username", std::move(nulLogin));
	auto nulPassword = ValidProxy();
	nulPassword.password = std::string("pass\0word", 9);
	add("NUL password", std::move(nulPassword));
	auto nulHost = ValidProxy();
	nulHost.host = std::string("127.0.0.1\0.invalid", 18);
	add("NUL host", std::move(nulHost));

	for (const auto &[name, proxy] : cases) {
		auto raw = ScriptedSocketFactory();
		auto failures = 0;
		auto factory = tgcalls::CreateGroupPacketSocketFactory(
			&raw,
			&proxy,
			[&] { ++failures; });
		auto socket = std::unique_ptr<rtc::AsyncPacketSocket>(
			factory->CreateUdpSocket(
				rtc::SocketAddress(rtc::GetAnyIP(AF_INET), 0),
				0,
				0));
		if (!Expect(!socket, "policy: accepted " + name)
			|| !Expect(raw.creates.empty(), "policy: raw socket for " + name)
			|| !Expect(
				failures == 1,
				"policy: failure callback was not exact for " + name)) {
			return false;
		}
	}
	return true;
}

[[nodiscard]] bool TestCreationFailureHasNoFallback() {
	const auto run = [](
			ScriptedSocketFactory &raw,
			const std::vector<std::pair<int, int>> &expected,
			const std::string &stage) {
		auto failures = 0;
		const auto proxy = ValidProxy();
		auto factory = tgcalls::CreateGroupPacketSocketFactory(
			&raw,
			&proxy,
			[&] { ++failures; });
		auto socket = std::unique_ptr<rtc::AsyncPacketSocket>(
			factory->CreateUdpSocket(
				rtc::SocketAddress(rtc::GetAnyIP(AF_INET), 0),
				0,
				0));
		return Expect(!socket, stage + ": socket creation did not fail")
			&& Expect(raw.creates == expected, stage + ": direct fallback created")
			&& Expect(failures == 1, stage + ": failure callback was not exact");
	};

	auto udp = ScriptedSocketFactory();
	udp.createUdp = false;
	if (!run(udp, { { AF_INET, SOCK_DGRAM } }, "UDP creation")) {
		return false;
	}
	auto tcp = ScriptedSocketFactory();
	tcp.createTcp = false;
	if (!run(
			tcp,
			{ { AF_INET, SOCK_DGRAM }, { AF_INET, SOCK_STREAM } },
			"control creation")) {
		return false;
	}
	auto connect = ScriptedSocketFactory();
	connect.tcpConnectFails = true;
	if (!run(
			connect,
			{ { AF_INET, SOCK_DGRAM }, { AF_INET, SOCK_STREAM } },
			"proxy connect")) {
		return false;
	}
	return Expect(
		connect.tcpTrace->connects
			== std::vector<rtc::SocketAddress>{
				rtc::SocketAddress(kProxyHost, kProxyPort),
			},
		"proxy connect: attempted a direct fallback");
}

[[nodiscard]] bool TestAuthenticationFailureHasNoFallback() {
	auto raw = ScriptedSocketFactory();
	auto failures = 0;
	const auto proxy = ValidProxy();
	auto factory = tgcalls::CreateGroupPacketSocketFactory(
		&raw,
		&proxy,
		[&] { ++failures; });
	auto socket = std::unique_ptr<rtc::AsyncPacketSocket>(
		factory->CreateUdpSocket(
			rtc::SocketAddress(rtc::GetAnyIP(AF_INET), 0),
			0,
			0));
	if (!Expect(socket != nullptr, "auth: socket was not created")
		|| !Expect(raw.tcp && raw.udp, "auth: raw sockets are missing")) {
		return false;
	}
	raw.tcp->CompleteConnect();
	raw.tcp->Receive({ 5, 2 });
	if (!Expect(
			raw.tcpTrace->sent == GreetingAndAuthentication(),
			"auth: exact credentials were not offered")) {
		return false;
	}
	raw.tcp->Receive({ 1, 1 });
	const auto closed = socket->GetState()
		== rtc::AsyncPacketSocket::STATE_CLOSED;
	socket.reset();
	return Expect(closed, "auth: rejection did not close the route")
		&& Expect(failures == 1, "auth: rejection callback was not exact")
		&& Expect(
			raw.udpTrace->connects.empty(),
			"auth: rejection attempted a UDP fallback")
		&& Expect(
			raw.tcpTrace->connects
				== std::vector<rtc::SocketAddress>{
					rtc::SocketAddress(kProxyHost, kProxyPort),
				},
			"auth: rejection attempted a TCP fallback");
}

[[nodiscard]] bool TestExternalRelayHasNoFallback() {
	auto raw = ScriptedSocketFactory();
	auto failures = 0;
	const auto proxy = ValidProxy();
	auto factory = tgcalls::CreateGroupPacketSocketFactory(
		&raw,
		&proxy,
		[&] { ++failures; });
	auto socket = std::unique_ptr<rtc::AsyncPacketSocket>(
		factory->CreateUdpSocket(
			rtc::SocketAddress(rtc::GetAnyIP(AF_INET), 0),
			0,
			0));
	if (!Expect(socket != nullptr, "relay: socket was not created")
		|| !Expect(
			AdvanceToAssociate(raw, failures),
			"relay: authenticated UDP ASSOCIATE request was wrong")) {
		return false;
	}
	raw.tcp->Receive(AssociateResponse({ 198, 51, 100, 10 }, kRelayPort));
	const auto closed = socket->GetState()
		== rtc::AsyncPacketSocket::STATE_CLOSED;
	socket.reset();
	return Expect(closed, "relay: external relay was not rejected")
		&& Expect(failures == 1, "relay: failure callback was not exact")
		&& Expect(
			raw.udpTrace->connects.empty(),
			"relay: external relay was contacted")
		&& Expect(
			raw.tcpTrace->connects
				== std::vector<rtc::SocketAddress>{
					rtc::SocketAddress(kProxyHost, kProxyPort),
				},
			"relay: rejection attempted a direct fallback");
}

[[nodiscard]] cricket::Candidate SafeCandidate() {
	auto result = cricket::Candidate();
	result.set_component(1);
	result.set_protocol("udp");
	result.set_address(rtc::SocketAddress(
		kPublicCandidateHost,
		kTargetPort));
	result.set_type("local");
	return result;
}

[[nodiscard]] bool TestCandidatePolicy() {
	const auto valid = SafeCandidate();
	if (!Expect(
			tgcalls::IsSafeManagedGroupCandidate(valid),
			"candidate: valid public UDP SFU was rejected")) {
		return false;
	}
	const auto rejected = [](cricket::Candidate candidate) {
		return !tgcalls::IsSafeManagedGroupCandidate(candidate);
	};
	auto secondComponent = valid;
	secondComponent.set_component(2);
	auto tcp = valid;
	tcp.set_protocol("tcp");
	auto documentation = valid;
	documentation.set_address(rtc::SocketAddress(kTargetHost, kTargetPort));
	return Expect(rejected(secondComponent), "candidate: component 2 accepted")
		&& Expect(rejected(tcp), "candidate: TCP accepted")
		&& Expect(
			rejected(documentation),
			"candidate: unsafe address bypassed address policy");
}

[[nodiscard]] bool TestAddressPolicy() {
	const auto accepted = [](const char *host) {
		return tgcalls::IsSafeManagedGroupAddress(
			rtc::SocketAddress(host, kTargetPort));
	};
	const auto rejected = [&](const char *host) {
		return !accepted(host);
	};
	if (!Expect(accepted(kPublicCandidateHost), "address: public IPv4 rejected")
		|| !Expect(
			accepted("2606:4700:4700::1111"),
			"address: public IPv6 rejected")) {
		return false;
	}

	auto scoped = rtc::SocketAddress("2606:4700:4700::1111", kTargetPort);
	scoped.SetScopeID(1);
	return Expect(
			!tgcalls::IsSafeManagedGroupAddress(scoped),
			"address: scoped public IPv6 accepted")
		&& Expect(
			!tgcalls::IsSafeManagedGroupAddress(
				rtc::SocketAddress(kPublicCandidateHost, 0)),
			"address: port zero accepted")
		&& Expect(rejected("sfu.invalid"), "address: unresolved host accepted")
		&& Expect(rejected("0.0.0.0"), "address: IPv4 wildcard accepted")
		&& Expect(rejected("127.0.0.1"), "address: IPv4 loopback accepted")
		&& Expect(rejected("10.0.0.1"), "address: private IPv4 accepted")
		&& Expect(rejected("100.64.0.1"), "address: CGNAT accepted")
		&& Expect(
			rejected("169.254.1.1"),
			"address: IPv4 link-local accepted")
		&& Expect(rejected("224.0.0.1"), "address: IPv4 multicast accepted")
		&& Expect(
			rejected("255.255.255.255"),
			"address: limited broadcast accepted")
		&& Expect(
			rejected("192.0.2.1"),
			"address: TEST-NET-1 accepted")
		&& Expect(
			rejected("198.51.100.10"),
			"address: TEST-NET-2 accepted")
		&& Expect(
			rejected("203.0.113.1"),
			"address: TEST-NET-3 accepted")
		&& Expect(rejected("::"), "address: IPv6 wildcard accepted")
		&& Expect(rejected("::1"), "address: IPv6 loopback accepted")
		&& Expect(rejected("fc00::1"), "address: unique-local IPv6 accepted")
		&& Expect(rejected("fe80::1"), "address: IPv6 link-local accepted")
		&& Expect(rejected("ff02::1"), "address: IPv6 multicast accepted")
		&& Expect(rejected("2001::1"), "address: Teredo IPv6 accepted")
		&& Expect(
			rejected("2001:2::1"),
			"address: benchmarking IPv6 accepted")
		&& Expect(rejected("2001:10::1"), "address: ORCHID IPv6 accepted")
		&& Expect(rejected("2001:20::1"), "address: ORCHIDv2 IPv6 accepted")
		&& Expect(
			rejected("2001:db8::1"),
			"address: documentation IPv6 accepted")
		&& Expect(rejected("2002::1"), "address: 6to4 IPv6 accepted")
		&& Expect(
			rejected("3fff::1"),
			"address: second documentation IPv6 accepted");
}

[[nodiscard]] bool RunPolicyTests() {
	return TestMainAndPresentationUseManagedUdp()
		&& TestUnmanagedRouteUsesStandardFactory()
		&& TestInvalidManagedPolicyCreatesNoSocket()
		&& TestCreationFailureHasNoFallback()
		&& TestAuthenticationFailureHasNoFallback()
		&& TestExternalRelayHasNoFallback()
		&& TestCandidatePolicy()
		&& TestAddressPolicy();
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

struct LiveRoute {
	std::unique_ptr<rtc::PacketSocketFactory> factory;
	std::unique_ptr<rtc::AsyncPacketSocket> socket;
	std::vector<uint8_t> received;
	rtc::SocketAddress source;
	int failures = 0;
};

[[nodiscard]] bool StartLiveRoute(
		LiveRoute &route,
		rtc::SocketFactory *socketFactory,
		const tgcalls::Proxy &proxy,
		const rtc::SocketAddress &target,
		const std::string &probe) {
	route.factory = tgcalls::CreateGroupPacketSocketFactory(
		socketFactory,
		&proxy,
		[&route] { ++route.failures; });
	route.socket.reset(route.factory->CreateUdpSocket(
		rtc::SocketAddress(rtc::GetAnyIP(AF_INET), 0),
		0,
		0));
	if (!route.socket) {
		return false;
	}
	route.socket->RegisterReceivedPacketCallback([&route](
			rtc::AsyncPacketSocket *,
			const rtc::ReceivedPacket &packet) {
		route.received.assign(
			packet.payload().begin(),
			packet.payload().end());
		route.source = packet.source_address();
	});
	return route.socket->SendTo(
		probe.data(),
		probe.size(),
		target,
		rtc::PacketOptions()) == int(probe.size());
}

void StopLiveRoute(LiveRoute &route) {
	if (route.socket) {
		route.socket->DeregisterReceivedPacketCallback();
		route.socket->Close();
		route.socket.reset();
	}
	route.factory.reset();
}

[[nodiscard]] bool RunLiveRoute() {
	const auto proxyHost = RequiredEnvironment("NO_DIRECT_EGRESS_PROXY_HOST");
	const auto proxyPortText = RequiredEnvironment(
		"NO_DIRECT_EGRESS_PROXY_PORT");
	const auto username = RequiredEnvironment(
		"NO_DIRECT_EGRESS_PROXY_USERNAME");
	const auto password = RequiredEnvironment(
		"NO_DIRECT_EGRESS_PROXY_PASSWORD");
	const auto targetHost = RequiredEnvironment("NO_DIRECT_EGRESS_TARGET_HOST");
	const auto targetPortText = RequiredEnvironment(
		"NO_DIRECT_EGRESS_TARGET_PORT");
	const auto mainProbe = RequiredEnvironment(
		"NO_DIRECT_EGRESS_GROUP_MAIN_UDP_PROBE");
	const auto mainReply = RequiredEnvironment(
		"NO_DIRECT_EGRESS_GROUP_MAIN_UDP_REPLY");
	const auto presentationProbe = RequiredEnvironment(
		"NO_DIRECT_EGRESS_GROUP_PRESENTATION_UDP_PROBE");
	const auto presentationReply = RequiredEnvironment(
		"NO_DIRECT_EGRESS_GROUP_PRESENTATION_UDP_REPLY");
	if (!proxyHost
		|| !proxyPortText
		|| !username
		|| !password
		|| !targetHost
		|| !targetPortText
		|| !mainProbe
		|| !mainReply
		|| !presentationProbe
		|| !presentationReply) {
		return false;
	}

	auto proxyPort = uint16_t();
	auto targetPort = uint16_t();
	if (std::string(proxyHost) != kProxyHost
		|| std::string(username) != kUsername
		|| std::string(password) != kPassword
		|| std::string(targetHost) != kTargetHost
		|| std::string(mainProbe) != kMainProbe
		|| std::string(mainReply) != kMainReply
		|| std::string(presentationProbe) != kPresentationProbe
		|| std::string(presentationReply) != kPresentationReply
		|| !ParsePort(proxyPortText, proxyPort)
		|| !ParsePort(targetPortText, targetPort)
		|| targetPort != kTargetPort) {
		std::cerr << "Refusing non-synthetic group proxy test input.\n";
		return false;
	}

	auto socketServer = rtc::PhysicalSocketServer();
	auto thread = rtc::AutoSocketServerThread(&socketServer);
	const auto proxy = ValidProxy(proxyPort);
	const auto target = rtc::SocketAddress(targetHost, targetPort);
	auto main = LiveRoute();
	auto presentation = LiveRoute();
	if (!StartLiveRoute(main, &socketServer, proxy, target, mainProbe)
		|| !StartLiveRoute(
			presentation,
			&socketServer,
			proxy,
			target,
			presentationProbe)) {
		std::cerr << "Could not start both synthetic group routes.\n";
		StopLiveRoute(presentation);
		StopLiveRoute(main);
		return false;
	}

	const auto deadline = rtc::TimeMillis() + kRouteTimeoutMs;
	while ((main.received.empty() || presentation.received.empty())
		&& !main.failures
		&& !presentation.failures) {
		const auto remaining = deadline - rtc::TimeMillis();
		if (remaining <= 0) {
			break;
		}
		thread.ProcessMessages(int(std::min<int64_t>(remaining, 20)));
	}

	const auto mainExpected = std::vector<uint8_t>(
		mainReply,
		mainReply + std::strlen(mainReply));
	const auto presentationExpected = std::vector<uint8_t>(
		presentationReply,
		presentationReply + std::strlen(presentationReply));
	const auto succeeded = !main.failures
		&& !presentation.failures
		&& main.received == mainExpected
		&& presentation.received == presentationExpected
		&& main.source == target
		&& presentation.source == target;
	StopLiveRoute(presentation);
	StopLiveRoute(main);
	if (!succeeded) {
		std::cerr << "Synthetic group SOCKS5 UDP routes did not succeed.\n";
	}
	return succeeded;
}

} // namespace

int main(int argc, char *argv[]) {
	if (argc == 2 && std::string(argv[1]) == "--policy-only") {
		return RunPolicyTests() ? 0 : 1;
	} else if (argc == 2 && std::string(argv[1]) == "--live-route") {
		return RunPolicyTests() && RunLiveRoute() ? 0 : 1;
	}
	std::cerr << "Usage: test_group_proxy_route "
		"[--policy-only|--live-route]\n";
	return 2;
}
