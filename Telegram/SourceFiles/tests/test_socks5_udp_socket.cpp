/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "v2/Socks5UdpSocketFactory.h"

#include "rtc_base/network/received_packet.h"
#include "rtc_base/async_packet_socket.h"
#include "rtc_base/buffer.h"
#include "rtc_base/crypt_string.h"
#include "rtc_base/ip_address.h"
#include "rtc_base/physical_socket_server.h"
#include "rtc_base/proxy_info.h"
#include "rtc_base/socket_factory.h"
#include "rtc_base/thread.h"
#include "rtc_base/time_utils.h"

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
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
constexpr auto kTargetHost = "198.51.100.10";
constexpr auto kTargetPort = uint16_t(443);
constexpr auto kRelayPort = uint16_t(40123);
constexpr auto kUsername = "synthetic-user";
constexpr auto kPassword = "synthetic-password";
constexpr auto kProbe = "synthetic-call-udp-probe";
constexpr auto kReply = "synthetic-call-udp-reply";
constexpr auto kRouteTimeoutMs = 3000;

enum class SendActionType {
	Limit,
	WouldBlock,
	Failure,
};

struct SendAction {
	SendActionType type = SendActionType::Limit;
	size_t limit = 0;
	int error = 0;
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

class ScriptedSocket final : public rtc::Socket {
public:
	ScriptedSocket();
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
	void NotifyWritable();
	void Receive(std::vector<uint8_t> bytes);
	void RemoteClose(int error);
	void QueueSendLimit(size_t limit);
	void QueueWouldBlock();
	void QueueFailure(int error);
	void SetSynchronousClose(int error);

	[[nodiscard]] const std::vector<rtc::SocketAddress> &connects() const;
	[[nodiscard]] const std::vector<uint8_t> &sent() const;
	[[nodiscard]] int addressedSends() const;
	[[nodiscard]] int closeCalls() const;

private:
	rtc::SocketAddress _localAddress;
	rtc::SocketAddress _remoteAddress;
	std::vector<rtc::SocketAddress> _binds;
	std::vector<rtc::SocketAddress> _connects;
	std::vector<uint8_t> _sent;
	std::vector<uint8_t> _input;
	std::deque<SendAction> _sendActions;
	ConnState _state = CS_CLOSED;
	int _error = 0;
	int _addressedSends = 0;
	int _closeCalls = 0;
	int _synchronousCloseError = 0;
	bool _synchronousClose = false;

};

class ScriptedSocketFactory final : public rtc::SocketFactory {
public:
	rtc::Socket *CreateSocket(int family, int type) override;

	ScriptedSocket *tcp = nullptr;
	ScriptedSocket *udp = nullptr;
	std::vector<std::pair<int, int>> creates;

};

class SocketObserver final : public sigslot::has_slots<> {
public:
	void AddressReady(
		rtc::AsyncPacketSocket *socket,
		const rtc::SocketAddress &address);
	void ReadyToSend(rtc::AsyncPacketSocket *socket);

	int addressReadyCount = 0;
	int readyToSendCount = 0;
	int closeCount = 0;
	int closeError = 0;
	bool received = false;
	bool reenterClose = false;
	std::vector<uint8_t> receivedPayload;
	rtc::SocketAddress receivedSource;

};

class Fixture final {
public:
	Fixture();
	~Fixture();

	bool AdvanceToAssociate();

	ScriptedSocketFactory factory;
	SocketObserver observer;
	std::unique_ptr<rtc::AsyncPacketSocket> socket;

};

static_assert(!std::is_abstract_v<ScriptedSocket>);

SyntheticCryptString::SyntheticCryptString(std::string value)
: _value(std::move(value)) {
}

size_t SyntheticCryptString::GetLength() const {
	return _value.size();
}

void SyntheticCryptString::CopyTo(
		char *destination,
		bool nullTerminate) const {
	std::memcpy(destination, _value.data(), _value.size());
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

ScriptedSocket::ScriptedSocket() {
}

rtc::SocketAddress ScriptedSocket::GetLocalAddress() const {
	return _localAddress;
}

rtc::SocketAddress ScriptedSocket::GetRemoteAddress() const {
	return _remoteAddress;
}

int ScriptedSocket::Bind(const rtc::SocketAddress &address) {
	_localAddress = address;
	_binds.push_back(address);
	return 0;
}

int ScriptedSocket::Connect(const rtc::SocketAddress &address) {
	_remoteAddress = address;
	_connects.push_back(address);
	_state = CS_CONNECTING;
	return 0;
}

int ScriptedSocket::Send(const void *data, size_t size) {
	if (!_sendActions.empty()) {
		const auto action = _sendActions.front();
		_sendActions.pop_front();
		if (action.type == SendActionType::WouldBlock
			|| action.type == SendActionType::Failure) {
			_error = action.error;
			return -1;
		}
		size = std::min(size, action.limit);
	}
	const auto bytes = static_cast<const uint8_t*>(data);
	_sent.insert(_sent.end(), bytes, bytes + size);
	_error = 0;
	return static_cast<int>(size);
}

int ScriptedSocket::SendTo(
		const void *data,
		size_t size,
		const rtc::SocketAddress &) {
	++_addressedSends;
	return Send(data, size);
}

int ScriptedSocket::Recv(void *data, size_t size, int64_t *timestamp) {
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
	const auto count = static_cast<int>(_input.size());
	_input.clear();
	_error = 0;
	return count;
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
	++_closeCalls;
	_state = CS_CLOSED;
	if (_synchronousClose) {
		SignalCloseEvent(this, _synchronousCloseError);
	}
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

int ScriptedSocket::SetOption(Option, int) {
	return 0;
}

void ScriptedSocket::CompleteConnect() {
	_state = CS_CONNECTED;
	_error = 0;
	SignalConnectEvent(this);
}

void ScriptedSocket::NotifyWritable() {
	SignalWriteEvent(this);
}

void ScriptedSocket::Receive(std::vector<uint8_t> bytes) {
	_input.insert(_input.end(), bytes.begin(), bytes.end());
	SignalReadEvent(this);
}

void ScriptedSocket::QueueSendLimit(size_t limit) {
	_sendActions.push_back({ SendActionType::Limit, limit, 0 });
}

void ScriptedSocket::QueueWouldBlock() {
	_sendActions.push_back({ SendActionType::WouldBlock, 0, EWOULDBLOCK });
}

void ScriptedSocket::QueueFailure(int error) {
	_sendActions.push_back({ SendActionType::Failure, 0, error });
}

void ScriptedSocket::SetSynchronousClose(int error) {
	_synchronousClose = true;
	_synchronousCloseError = error;
}

void ScriptedSocket::RemoteClose(int error) {
	_state = CS_CLOSED;
	_error = error;
	SignalCloseEvent(this, error);
}

const std::vector<rtc::SocketAddress> &ScriptedSocket::connects() const {
	return _connects;
}

const std::vector<uint8_t> &ScriptedSocket::sent() const {
	return _sent;
}

int ScriptedSocket::addressedSends() const {
	return _addressedSends;
}

int ScriptedSocket::closeCalls() const {
	return _closeCalls;
}

rtc::Socket *ScriptedSocketFactory::CreateSocket(int family, int type) {
	creates.emplace_back(family, type);
	auto owned = std::make_unique<ScriptedSocket>();
	const auto result = owned.get();
	if (type == SOCK_STREAM && !tcp) {
		tcp = result;
	} else if (type == SOCK_DGRAM && !udp) {
		udp = result;
	} else {
		return nullptr;
	}
	return owned.release();
}

void SocketObserver::AddressReady(
		rtc::AsyncPacketSocket *,
		const rtc::SocketAddress &) {
	++addressReadyCount;
}

void SocketObserver::ReadyToSend(rtc::AsyncPacketSocket *) {
	++readyToSendCount;
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
	result.username = kUsername;
	const auto password = SyntheticCryptString(kPassword);
	result.password = rtc::CryptString(password);
	return result;
}

[[nodiscard]] std::vector<uint8_t> GreetingRequest() {
	return { 5, 1, 2 };
}

[[nodiscard]] std::vector<uint8_t> AuthenticationRequest() {
	auto result = std::vector<uint8_t>{
		1,
		uint8_t(std::strlen(kUsername)),
	};
	result.insert(result.end(), kUsername, kUsername + std::strlen(kUsername));
	result.push_back(uint8_t(std::strlen(kPassword)));
	result.insert(result.end(), kPassword, kPassword + std::strlen(kPassword));
	return result;
}

[[nodiscard]] std::vector<uint8_t> AssociateRequest() {
	return { 5, 3, 0, 1, 0, 0, 0, 0, 0, 0 };
}

[[nodiscard]] std::vector<uint8_t> AssociateResponse(
		const rtc::SocketAddress &relay) {
	const auto ip = relay.ipaddr().v4AddressAsHostOrderInteger();
	return {
		5,
		0,
		0,
		1,
		uint8_t(ip >> 24),
		uint8_t(ip >> 16),
		uint8_t(ip >> 8),
		uint8_t(ip),
		uint8_t(relay.port() >> 8),
		uint8_t(relay.port()),
	};
}

[[nodiscard]] std::vector<uint8_t> Framed(
		const rtc::SocketAddress &target,
		const std::string &payload) {
	const auto ip = target.ipaddr().v4AddressAsHostOrderInteger();
	auto result = std::vector<uint8_t>{
		0,
		0,
		0,
		1,
		uint8_t(ip >> 24),
		uint8_t(ip >> 16),
		uint8_t(ip >> 8),
		uint8_t(ip),
		uint8_t(target.port() >> 8),
		uint8_t(target.port()),
	};
	result.insert(result.end(), payload.begin(), payload.end());
	return result;
}

void Append(
		std::vector<uint8_t> &destination,
		const std::vector<uint8_t> &source) {
	destination.insert(destination.end(), source.begin(), source.end());
}

Fixture::Fixture() {
	const auto proxy = AuthenticatedProxy(
		rtc::SocketAddress(kProxyHost, kProxyPort));
	socket.reset(tgcalls::CreateSocks5UdpSocket(&factory, proxy));
	if (!socket) {
		return;
	}
	socket->SignalAddressReady.connect(
		&observer,
		&SocketObserver::AddressReady);
	socket->SignalReadyToSend.connect(
		&observer,
		&SocketObserver::ReadyToSend);
	socket->SubscribeCloseEvent(&observer, [this](
			rtc::AsyncPacketSocket *closed,
			int error) {
		++observer.closeCount;
		observer.closeError = error;
		if (observer.reenterClose) {
			closed->Close();
		}
	});
	socket->RegisterReceivedPacketCallback([this](
			rtc::AsyncPacketSocket *,
			const rtc::ReceivedPacket &packet) {
		observer.received = true;
		observer.receivedPayload.assign(
			packet.payload().begin(),
			packet.payload().end());
		observer.receivedSource = packet.source_address();
	});
}

Fixture::~Fixture() {
	if (socket) {
		socket->DeregisterReceivedPacketCallback();
		socket->UnsubscribeCloseEvent(&observer);
	}
}

bool Fixture::AdvanceToAssociate() {
	if (!socket || !factory.tcp || !factory.udp) {
		return false;
	}
	const auto proxy = rtc::SocketAddress(kProxyHost, kProxyPort);
	if (factory.tcp->connects()
			!= std::vector<rtc::SocketAddress>{ proxy }) {
		return false;
	}
	factory.tcp->CompleteConnect();
	if (factory.tcp->sent() != GreetingRequest()) {
		return false;
	}
	factory.tcp->Receive({ 5, 2 });
	auto expected = GreetingRequest();
	Append(expected, AuthenticationRequest());
	if (factory.tcp->sent() != expected) {
		return false;
	}
	factory.tcp->Receive({ 1, 0 });
	Append(expected, AssociateRequest());
	return factory.tcp->sent() == expected;
}

enum class ControlPhase {
	Initial,
	Greeting,
	Authentication,
	Association,
	RelayConnecting,
	Ready,
};

[[nodiscard]] bool ReachPhase(Fixture &fixture, ControlPhase phase) {
	if (!fixture.socket || !fixture.factory.tcp || !fixture.factory.udp) {
		return false;
	}
	if (phase == ControlPhase::Initial) {
		return true;
	}
	fixture.factory.tcp->CompleteConnect();
	if (phase == ControlPhase::Greeting) {
		return true;
	}
	fixture.factory.tcp->Receive({ 5, 2 });
	if (phase == ControlPhase::Authentication) {
		return true;
	}
	fixture.factory.tcp->Receive({ 1, 0 });
	if (phase == ControlPhase::Association) {
		return true;
	}
	fixture.factory.tcp->Receive(AssociateResponse(
		rtc::SocketAddress(kProxyHost, kRelayPort)));
	if (phase == ControlPhase::RelayConnecting) {
		return true;
	}
	fixture.factory.udp->CompleteConnect();
	return true;
}

[[nodiscard]] bool TestPartialWritesAndFragmentedReplies() {
	auto fixture = Fixture();
	fixture.factory.tcp->QueueSendLimit(1);
	fixture.factory.tcp->QueueWouldBlock();
	fixture.factory.tcp->CompleteConnect();
	if (!Expect(
			fixture.factory.tcp->sent() == std::vector<uint8_t>{ 5 },
			"partial: greeting prefix was wrong")) {
		return false;
	}
	fixture.factory.tcp->QueueSendLimit(1);
	fixture.factory.tcp->QueueWouldBlock();
	fixture.factory.tcp->NotifyWritable();
	if (!Expect(
			fixture.factory.tcp->sent() == std::vector<uint8_t>{ 5, 1 },
			"partial: greeting middle byte was wrong")) {
		return false;
	}
	fixture.factory.tcp->NotifyWritable();
	if (!Expect(
			fixture.factory.tcp->sent() == GreetingRequest(),
			"partial: greeting did not finish")) {
		return false;
	}

	fixture.factory.tcp->QueueSendLimit(3);
	fixture.factory.tcp->QueueWouldBlock();
	fixture.factory.tcp->Receive({ 5 });
	if (!Expect(
			fixture.factory.tcp->sent() == GreetingRequest(),
			"fragmented greeting advanced early")) {
		return false;
	}
	fixture.factory.tcp->Receive({ 2 });
	auto expected = GreetingRequest();
	const auto authentication = AuthenticationRequest();
	expected.insert(
		expected.end(),
		authentication.begin(),
		authentication.begin() + 3);
	if (!Expect(
			fixture.factory.tcp->sent() == expected,
			"partial: authentication prefix was wrong")) {
		return false;
	}
	fixture.factory.tcp->NotifyWritable();
	expected = GreetingRequest();
	Append(expected, authentication);
	if (!Expect(
			fixture.factory.tcp->sent() == expected,
			"partial: authentication did not finish")) {
		return false;
	}

	fixture.factory.tcp->QueueSendLimit(2);
	fixture.factory.tcp->QueueWouldBlock();
	fixture.factory.tcp->Receive({ 1 });
	fixture.factory.tcp->Receive({ 0 });
	const auto association = AssociateRequest();
	expected.insert(
		expected.end(),
		association.begin(),
		association.begin() + 2);
	if (!Expect(
			fixture.factory.tcp->sent() == expected,
			"partial: association prefix was wrong")) {
		return false;
	}
	fixture.factory.tcp->NotifyWritable();
	expected = GreetingRequest();
	Append(expected, authentication);
	Append(expected, association);
	if (!Expect(
			fixture.factory.tcp->sent() == expected,
			"partial: association did not finish")) {
		return false;
	}

	const auto response = AssociateResponse(
		rtc::SocketAddress(kProxyHost, kRelayPort));
	for (const auto byte : response) {
		fixture.factory.tcp->Receive({ byte });
	}
	if (!Expect(
			fixture.factory.udp->connects()
				== std::vector<rtc::SocketAddress>{
					rtc::SocketAddress(kProxyHost, kRelayPort) },
			"fragmented association did not select the relay")) {
		return false;
	}
	fixture.factory.udp->CompleteConnect();
	return Expect(
		fixture.socket->GetState() == rtc::AsyncPacketSocket::STATE_BOUND
			&& fixture.observer.addressReadyCount == 1
			&& fixture.observer.readyToSendCount == 1,
		"fragmented association did not become ready");
}

struct MalformedControlCase {
	const char *name = nullptr;
	ControlPhase phase = ControlPhase::Initial;
	std::vector<uint8_t> response;
};

[[nodiscard]] bool TestMalformedControlReplies() {
	auto zeroPort = AssociateResponse(
		rtc::SocketAddress(kProxyHost, kRelayPort));
	zeroPort[8] = 0;
	zeroPort[9] = 0;
	auto residual = AssociateResponse(
		rtc::SocketAddress(kProxyHost, kRelayPort));
	residual.push_back(0);
	const auto cases = std::vector<MalformedControlCase>{
		{ "greeting version", ControlPhase::Greeting, { 4, 2 } },
		{ "greeting method", ControlPhase::Greeting, { 5, 0 } },
		{ "greeting residual", ControlPhase::Greeting, { 5, 2, 0 } },
		{ "authentication version", ControlPhase::Authentication, { 2, 0 } },
		{ "authentication status", ControlPhase::Authentication, { 1, 1 } },
		{ "authentication residual", ControlPhase::Authentication, { 1, 0, 0 } },
		{ "association version", ControlPhase::Association, { 4, 0, 0, 1 } },
		{ "association reply", ControlPhase::Association, { 5, 1, 0, 1 } },
		{ "association reserved", ControlPhase::Association, { 5, 0, 1, 1 } },
		{ "association domain", ControlPhase::Association, { 5, 0, 0, 3 } },
		{ "association zero port", ControlPhase::Association, zeroPort },
		{ "association residual", ControlPhase::Association, residual },
	};
	for (const auto &test : cases) {
		auto fixture = Fixture();
		if (!Expect(ReachPhase(fixture, test.phase), test.name)) {
			return false;
		}
		fixture.factory.tcp->Receive(test.response);
		fixture.factory.tcp->RemoteClose(ECONNABORTED);
		if (!Expect(
				fixture.observer.closeCount == 1
					&& fixture.socket->GetState()
						== rtc::AsyncPacketSocket::STATE_CLOSED
					&& fixture.factory.udp->connects().empty(),
				test.name)) {
			return false;
		}
	}
	return true;
}

[[nodiscard]] bool TestMalformedRelayFrame() {
	auto fixture = Fixture();
	if (!Expect(
			ReachPhase(fixture, ControlPhase::Ready),
			"relay frame: could not become ready")) {
		return false;
	}
	auto fragmented = Framed(
		rtc::SocketAddress(kTargetHost, kTargetPort),
		kReply);
	fragmented[2] = 1;
	fixture.factory.udp->Receive(std::move(fragmented));
	fixture.factory.udp->RemoteClose(ECONNABORTED);
	return Expect(
		fixture.observer.closeCount == 1
			&& !fixture.observer.received
			&& fixture.socket->GetState()
				== rtc::AsyncPacketSocket::STATE_CLOSED,
		"relay frame: FRAG was accepted or close repeated");
}

[[nodiscard]] bool TestRemoteCloseEveryPhase() {
	const auto phases = std::vector<ControlPhase>{
		ControlPhase::Initial,
		ControlPhase::Greeting,
		ControlPhase::Authentication,
		ControlPhase::Association,
		ControlPhase::RelayConnecting,
		ControlPhase::Ready,
	};
	for (const auto phase : phases) {
		auto fixture = Fixture();
		if (!Expect(
				ReachPhase(fixture, phase),
				"remote close: could not reach phase")) {
			return false;
		}
		const auto transport = (phase == ControlPhase::RelayConnecting)
			? fixture.factory.udp
			: fixture.factory.tcp;
		transport->RemoteClose(ECONNABORTED);
		transport->RemoteClose(ECONNABORTED);
		if (!Expect(
				fixture.observer.closeCount == 1
					&& fixture.observer.closeError == ECONNABORTED
					&& fixture.socket->GetState()
						== rtc::AsyncPacketSocket::STATE_CLOSED,
				"remote close: terminal notification was not exact")) {
			return false;
		}
	}
	return true;
}

[[nodiscard]] bool TestQueueBounds() {
	auto fixture = Fixture();
	const auto target = rtc::SocketAddress(kTargetHost, kTargetPort);
	const auto payload = std::vector<uint8_t>(4096, 0x5A);
	for (auto i = 0; i != 16; ++i) {
		if (!Expect(
				fixture.socket->SendTo(
					payload.data(),
					payload.size(),
					target,
					rtc::PacketOptions()) == int(payload.size()),
				"queue: bounded packet was rejected")) {
			return false;
		}
	}
	if (!Expect(
			fixture.socket->SendTo(
				payload.data(),
				payload.size(),
				target,
				rtc::PacketOptions()) < 0,
			"queue: seventeenth packet was accepted")) {
		return false;
	}
	if (!Expect(
			ReachPhase(fixture, ControlPhase::Ready),
			"queue: could not flush through association")) {
		return false;
	}
	return Expect(
		fixture.factory.udp->sent().size() == 16 * (payload.size() + 10)
			&& fixture.factory.udp->addressedSends() == 0,
		"queue: packets were not framed or used addressed sends");
}

[[nodiscard]] bool TestSynchronousCloseReentrancy() {
	auto fixture = Fixture();
	fixture.observer.reenterClose = true;
	fixture.factory.tcp->SetSynchronousClose(ECONNABORTED);
	if (!Expect(
			ReachPhase(fixture, ControlPhase::Greeting),
			"reentrant close: could not reach greeting")) {
		return false;
	}
	fixture.factory.tcp->Receive({ 4, 2 });
	fixture.factory.tcp->RemoteClose(ECONNABORTED);
	return Expect(
		fixture.observer.closeCount == 1
			&& fixture.factory.tcp->closeCalls() == 1
			&& fixture.factory.udp->closeCalls() == 1
			&& fixture.socket->GetState()
				== rtc::AsyncPacketSocket::STATE_CLOSED,
		"reentrant close: close escaped terminal suppression");
}

[[nodiscard]] bool TestRelaySendFailureClosesOnce() {
	auto fixture = Fixture();
	if (!Expect(
			ReachPhase(fixture, ControlPhase::Ready),
			"send failure: could not become ready")) {
		return false;
	}
	fixture.factory.udp->QueueFailure(ECONNABORTED);
	const auto payload = std::string(kProbe);
	const auto target = rtc::SocketAddress(kTargetHost, kTargetPort);
	const auto sent = fixture.socket->SendTo(
		payload.data(),
		payload.size(),
		target,
		rtc::PacketOptions());
	fixture.factory.udp->RemoteClose(ECONNABORTED);
	return Expect(
		sent < 0
			&& fixture.observer.closeCount == 1
			&& fixture.socket->GetState()
				== rtc::AsyncPacketSocket::STATE_CLOSED,
		"send failure: route did not fail exactly once");
}

[[nodiscard]] bool TestAuthenticatedAssociation() {
	auto fixture = Fixture();
	const auto target = rtc::SocketAddress(kTargetHost, kTargetPort);
	const auto probe = std::string(kProbe);
	if (!Expect(
			fixture.socket != nullptr,
			"association: socket was not created")
		|| !Expect(
			fixture.factory.tcp != nullptr
				&& fixture.factory.udp != nullptr
				&& fixture.socket->GetState()
					== rtc::AsyncPacketSocket::STATE_BINDING,
			"association: initial sockets or state were wrong")
		|| !Expect(
			fixture.socket->SendTo(
				probe.data(),
				probe.size(),
				target,
				rtc::PacketOptions()) == int(probe.size()),
			"association: bounded pre-association packet was rejected")
		|| !Expect(
			fixture.factory.udp->sent().empty(),
			"association: packet bypassed the proxy handshake")
		|| !Expect(
			fixture.AdvanceToAssociate(),
			"association: authenticated handshake was wrong")) {
		return false;
	}

	const auto relay = rtc::SocketAddress(kProxyHost, kRelayPort);
	fixture.factory.tcp->Receive(AssociateResponse(relay));
	if (!Expect(
			fixture.factory.udp->connects()
				== std::vector<rtc::SocketAddress>{ relay },
			"association: UDP socket connected anywhere except the relay")
		|| !Expect(
			fixture.factory.udp->sent().empty(),
			"association: packet was sent before relay connection")) {
		return false;
	}

	fixture.factory.udp->CompleteConnect();
	if (!Expect(
			fixture.socket->GetState()
				== rtc::AsyncPacketSocket::STATE_BOUND
				&& fixture.observer.addressReadyCount == 1
				&& fixture.observer.readyToSendCount == 1
				&& fixture.observer.closeCount == 0,
			"association: ready state or signals were wrong")
		|| !Expect(
			fixture.factory.udp->sent() == Framed(target, probe)
				&& fixture.factory.udp->addressedSends() == 0,
			"association: UDP payload did not use an unaddressed SOCKS frame")) {
		return false;
	}

	fixture.factory.udp->Receive(Framed(target, kReply));
	return Expect(
		fixture.observer.received
			&& fixture.observer.receivedPayload
				== std::vector<uint8_t>(kReply, kReply + std::strlen(kReply))
			&& fixture.observer.receivedSource == target,
		"association: framed relay response was not decoded");
}

[[nodiscard]] bool TestInvalidPolicyCreatesNoSocket() {
	const auto valid = AuthenticatedProxy(
		rtc::SocketAddress(kProxyHost, kProxyPort));
	const auto rejected = [](const rtc::ProxyInfo &proxy) {
		auto factory = ScriptedSocketFactory();
		auto socket = std::unique_ptr<rtc::AsyncPacketSocket>(
			tgcalls::CreateSocks5UdpSocket(&factory, proxy));
		return !socket && factory.creates.empty();
	};
	auto unsupported = valid;
	unsupported.type = rtc::PROXY_HTTPS;
	auto noUsername = valid;
	noUsername.username.clear();
	auto noPassword = valid;
	noPassword.password.Clear();
	auto unresolved = valid;
	unresolved.address = rtc::SocketAddress("proxy.invalid", kProxyPort);
	auto nonLoopback = valid;
	nonLoopback.address = rtc::SocketAddress(kTargetHost, kProxyPort);
	auto missingPort = valid;
	missingPort.address.SetPort(0);
	return Expect(rejected(unsupported), "policy: HTTPS proxy was accepted")
		&& Expect(rejected(noUsername), "policy: empty username was accepted")
		&& Expect(rejected(noPassword), "policy: empty password was accepted")
		&& Expect(rejected(unresolved), "policy: unresolved proxy was accepted")
		&& Expect(rejected(nonLoopback), "policy: non-loopback proxy was accepted")
		&& Expect(rejected(missingPort), "policy: portless proxy was accepted")
		&& Expect(
			tgcalls::CreateSocks5UdpSocket(nullptr, valid) == nullptr,
			"policy: null socket factory was accepted");
}

[[nodiscard]] bool TestRelayCannotEscapeLoopback() {
	auto fixture = Fixture();
	if (!Expect(
			fixture.AdvanceToAssociate(),
			"relay policy: could not reach ASSOCIATE")) {
		return false;
	}
	const auto external = rtc::SocketAddress(kTargetHost, kRelayPort);
	fixture.factory.tcp->Receive(AssociateResponse(external));
	fixture.factory.tcp->RemoteClose(ECONNABORTED);
	return Expect(
		fixture.factory.udp->connects().empty()
			&& fixture.observer.closeCount == 1
			&& fixture.socket->GetState()
				== rtc::AsyncPacketSocket::STATE_CLOSED,
		"relay policy: external relay or duplicate close was accepted");
}

[[nodiscard]] bool RunPolicyTests() {
	return TestPartialWritesAndFragmentedReplies()
		&& TestAuthenticatedAssociation()
		&& TestMalformedControlReplies()
		&& TestMalformedRelayFrame()
		&& TestRemoteCloseEveryPhase()
		&& TestQueueBounds()
		&& TestSynchronousCloseReentrancy()
		&& TestRelaySendFailureClosesOnce()
		&& TestInvalidPolicyCreatesNoSocket()
		&& TestRelayCannotEscapeLoopback();
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

[[nodiscard]] bool RunLiveRoute() {
	const auto proxyHost = RequiredEnvironment("NO_DIRECT_EGRESS_PROXY_HOST");
	const auto proxyPortText = RequiredEnvironment(
		"NO_DIRECT_EGRESS_PROXY_PORT");
	const auto proxyUsername = RequiredEnvironment(
		"NO_DIRECT_EGRESS_PROXY_USERNAME");
	const auto proxyPassword = RequiredEnvironment(
		"NO_DIRECT_EGRESS_PROXY_PASSWORD");
	const auto targetHost = RequiredEnvironment("NO_DIRECT_EGRESS_TARGET_HOST");
	const auto targetPortText = RequiredEnvironment(
		"NO_DIRECT_EGRESS_TARGET_PORT");
	const auto probe = RequiredEnvironment("NO_DIRECT_EGRESS_UDP_PROBE");
	const auto reply = RequiredEnvironment("NO_DIRECT_EGRESS_UDP_REPLY");
	if (!proxyHost
		|| !proxyPortText
		|| !proxyUsername
		|| !proxyPassword
		|| !targetHost
		|| !targetPortText
		|| !probe
		|| !reply) {
		return false;
	}

	auto proxyPort = uint16_t();
	auto targetPort = uint16_t();
	if (std::string(proxyHost) != kProxyHost
		|| std::string(proxyUsername) != kUsername
		|| std::string(proxyPassword) != kPassword
		|| std::string(targetHost) != kTargetHost
		|| std::string(probe) != kProbe
		|| std::string(reply) != kReply
		|| !ParsePort(proxyPortText, proxyPort)
		|| !ParsePort(targetPortText, targetPort)
		|| targetPort != kTargetPort) {
		std::cerr << "Refusing non-synthetic UDP proxy test input.\n";
		return false;
	}

	auto socketServer = rtc::PhysicalSocketServer();
	auto thread = rtc::AutoSocketServerThread(&socketServer);
	const auto proxy = AuthenticatedProxy(
		rtc::SocketAddress(proxyHost, proxyPort));
	auto socket = std::unique_ptr<rtc::AsyncPacketSocket>(
		tgcalls::CreateSocks5UdpSocket(&socketServer, proxy));
	if (!socket) {
		std::cerr << "Could not create the synthetic UDP proxy socket.\n";
		return false;
	}

	auto observer = SocketObserver();
	socket->SubscribeCloseEvent(&observer, [&observer](
			rtc::AsyncPacketSocket *,
			int error) {
		++observer.closeCount;
		observer.closeError = error;
	});
	socket->RegisterReceivedPacketCallback([&observer](
			rtc::AsyncPacketSocket *,
			const rtc::ReceivedPacket &packet) {
		observer.received = true;
		observer.receivedPayload.assign(
			packet.payload().begin(),
			packet.payload().end());
		observer.receivedSource = packet.source_address();
	});
	const auto target = rtc::SocketAddress(targetHost, targetPort);
	const auto probeValue = std::string(probe);
	if (socket->SendTo(
			probeValue.data(),
			probeValue.size(),
			target,
			rtc::PacketOptions()) != int(probeValue.size())) {
		std::cerr << "Synthetic UDP probe was not queued.\n";
		socket->DeregisterReceivedPacketCallback();
		socket->UnsubscribeCloseEvent(&observer);
		socket->Close();
		return false;
	}

	const auto deadline = rtc::TimeMillis() + kRouteTimeoutMs;
	while (!observer.received && !observer.closeCount) {
		const auto remaining = deadline - rtc::TimeMillis();
		if (remaining <= 0) {
			break;
		}
		thread.ProcessMessages(int(std::min<int64_t>(remaining, 20)));
	}

	socket->DeregisterReceivedPacketCallback();
	socket->UnsubscribeCloseEvent(&observer);
	socket->Close();
	const auto expected = std::vector<uint8_t>(
		reply,
		reply + std::strlen(reply));
	if (!observer.received
		|| observer.closeCount
		|| observer.receivedPayload != expected
		|| observer.receivedSource != target) {
		std::cerr << "Synthetic SOCKS5 UDP route did not succeed.\n";
		return false;
	}
	return true;
}

} // namespace

int main(int argc, char *argv[]) {
	if (argc == 1) {
		return RunPolicyTests() ? 0 : 1;
	} else if (argc == 2 && std::string(argv[1]) == "--live-route") {
		return RunPolicyTests() && RunLiveRoute() ? 0 : 1;
	}
	std::cerr << "Usage: test_socks5_udp_socket [--live-route]\n";
	return 2;
}
