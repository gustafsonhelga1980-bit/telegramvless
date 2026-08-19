/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "v2/Socks5ProxySocket.h"

#include "rtc_base/crypt_string.h"
#include "rtc_base/socket.h"
#include "rtc_base/socket_address.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
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
constexpr auto kTargetHost = "target.example";
constexpr auto kTargetPort = uint16_t(443);
constexpr auto kUsername = "synthetic-user";
constexpr auto kPassword = "synthetic-password";

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

enum class HandshakePhase {
	Initial,
	Greeting,
	Authentication,
	Connect,
	Tunnel,
};

struct MalformedCase {
	const char *name = nullptr;
	HandshakePhase phase = HandshakePhase::Initial;
	std::vector<uint8_t> response;
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
	ScriptedSocket() = default;
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

	void QueueSendLimit(size_t limit);
	void QueueWouldBlock();
	void QueueFailure(int error);
	void SetSynchronousClose(int error);
	void CompleteConnect();
	void NotifyWritable();
	void Receive(std::vector<uint8_t> bytes);
	void RemoteClose(int error);

	[[nodiscard]] const std::vector<uint8_t> &sent() const;
	[[nodiscard]] const std::vector<rtc::SocketAddress> &connects() const;
	[[nodiscard]] int closeCalls() const;

private:
	rtc::SocketAddress _localAddress;
	rtc::SocketAddress _remoteAddress;
	std::deque<SendAction> _sendActions;
	std::vector<uint8_t> _sent;
	std::vector<uint8_t> _input;
	std::vector<rtc::SocketAddress> _connects;
	ConnState _state = CS_CLOSED;
	int _error = 0;
	int _closeCalls = 0;
	int _synchronousCloseError = 0;
	bool _synchronousClose = false;

};

class SocketObserver final : public sigslot::has_slots<> {
public:
	void Connected(rtc::Socket *socket);
	void Writable(rtc::Socket *socket);
	void Closed(rtc::Socket *socket, int error);

	int connectCount = 0;
	int writeCount = 0;
	int closeCount = 0;
	int closeError = 0;

};

class Fixture final {
public:
	Fixture();

	bool Start();

	SocketObserver observer;
	ScriptedSocket *transport = nullptr;
	std::unique_ptr<tgcalls::Socks5ProxySocket> socket;

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

rtc::SocketAddress ScriptedSocket::GetLocalAddress() const {
	return _localAddress;
}

rtc::SocketAddress ScriptedSocket::GetRemoteAddress() const {
	return _remoteAddress;
}

int ScriptedSocket::Bind(const rtc::SocketAddress &address) {
	_localAddress = address;
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
		if (action.type == SendActionType::WouldBlock) {
			_error = action.error;
			return -1;
		} else if (action.type == SendActionType::Failure) {
			_error = action.error;
			return -1;
		}
		size = std::min(size, action.limit);
	}
	if (!size) {
		return 0;
	}
	const auto bytes = static_cast<const uint8_t*>(data);
	_sent.insert(_sent.end(), bytes, bytes + size);
	_error = 0;
	return static_cast<int>(size);
}

int ScriptedSocket::SendTo(
		const void *,
		size_t,
		const rtc::SocketAddress &) {
	_error = SOCKET_EACCES;
	return -1;
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

int ScriptedSocket::RecvFrom(ReceiveBuffer &) {
	_error = EWOULDBLOCK;
	return -1;
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

void ScriptedSocket::RemoteClose(int error) {
	_state = CS_CLOSED;
	_error = error;
	SignalCloseEvent(this, error);
}

const std::vector<uint8_t> &ScriptedSocket::sent() const {
	return _sent;
}

const std::vector<rtc::SocketAddress> &ScriptedSocket::connects() const {
	return _connects;
}

int ScriptedSocket::closeCalls() const {
	return _closeCalls;
}

void SocketObserver::Connected(rtc::Socket *) {
	++connectCount;
}

void SocketObserver::Writable(rtc::Socket *) {
	++writeCount;
}

void SocketObserver::Closed(rtc::Socket *, int error) {
	++closeCount;
	closeError = error;
}

Fixture::Fixture() {
	auto owned = std::make_unique<ScriptedSocket>();
	transport = owned.get();
	const auto password = SyntheticCryptString(kPassword);
	const auto credentials = rtc::CryptString(password);
	socket = std::unique_ptr<tgcalls::Socks5ProxySocket>(
		new tgcalls::Socks5ProxySocket(
			owned.release(),
			rtc::SocketAddress(kProxyHost, kProxyPort),
			kUsername,
			credentials));
	socket->SignalConnectEvent.connect(&observer, &SocketObserver::Connected);
	socket->SignalWriteEvent.connect(&observer, &SocketObserver::Writable);
	socket->SignalCloseEvent.connect(&observer, &SocketObserver::Closed);
}

bool Fixture::Start() {
	const auto proxy = rtc::SocketAddress(kProxyHost, kProxyPort);
	const auto destination = rtc::SocketAddress(kTargetHost, kTargetPort);
	return socket->Connect(destination) == 0
		&& transport->GetRemoteAddress() == proxy
		&& transport->connects()
			== std::vector<rtc::SocketAddress>{ proxy }
		&& socket->GetRemoteAddress() == destination
		&& socket->GetState() == rtc::Socket::CS_CONNECTING;
}

[[nodiscard]] bool Expect(bool condition, const char *message) {
	if (!condition) {
		std::fprintf(stderr, "%s\n", message);
	}
	return condition;
}

[[nodiscard]] std::vector<uint8_t> GreetingRequest() {
	return { 5, 1, 2 };
}

[[nodiscard]] std::vector<uint8_t> AuthenticationRequest() {
	auto result = std::vector<uint8_t>{ 1, uint8_t(std::strlen(kUsername)) };
	result.insert(
		result.end(),
		kUsername,
		kUsername + std::strlen(kUsername));
	result.push_back(uint8_t(std::strlen(kPassword)));
	result.insert(
		result.end(),
		kPassword,
		kPassword + std::strlen(kPassword));
	return result;
}

[[nodiscard]] std::vector<uint8_t> ConnectRequest() {
	auto result = std::vector<uint8_t>{
		5,
		1,
		0,
		3,
		uint8_t(std::strlen(kTargetHost)),
	};
	result.insert(
		result.end(),
		kTargetHost,
		kTargetHost + std::strlen(kTargetHost));
	result.push_back(uint8_t(kTargetPort >> 8));
	result.push_back(uint8_t(kTargetPort));
	return result;
}

[[nodiscard]] std::vector<uint8_t> ConnectResponse() {
	return { 5, 0, 0, 1, 127, 0, 0, 1, 0, 0 };
}

void Append(
		std::vector<uint8_t> &destination,
		const std::vector<uint8_t> &source) {
	destination.insert(destination.end(), source.begin(), source.end());
}

[[nodiscard]] bool ReachPhase(Fixture &fixture, HandshakePhase phase) {
	if (!fixture.Start()) {
		return false;
	}
	if (phase == HandshakePhase::Initial) {
		return true;
	}
	fixture.transport->CompleteConnect();
	if (phase == HandshakePhase::Greeting) {
		return true;
	}
	fixture.transport->Receive({ 5, 2 });
	if (phase == HandshakePhase::Authentication) {
		return true;
	}
	fixture.transport->Receive({ 1, 0 });
	if (phase == HandshakePhase::Connect) {
		return true;
	}
	fixture.transport->Receive(ConnectResponse());
	return fixture.observer.connectCount == 1;
}

[[nodiscard]] bool TestAuthenticatedConnectContract() {
	auto fixture = Fixture();
	if (!Expect(fixture.Start(), "contract: Connect failed")) {
		return false;
	}
	if (!Expect(
			fixture.transport->sent().empty()
				&& fixture.observer.connectCount == 0,
			"contract: handshake started before proxy connection")) {
		return false;
	}

	fixture.transport->CompleteConnect();
	if (!Expect(
			fixture.transport->sent() == GreetingRequest()
				&& fixture.observer.connectCount == 0,
			"contract: password-only greeting was wrong")) {
		return false;
	}

	fixture.transport->Receive({ 5, 2 });
	auto expected = GreetingRequest();
	Append(expected, AuthenticationRequest());
	if (!Expect(
			fixture.transport->sent() == expected
				&& fixture.observer.connectCount == 0,
			"contract: authenticated request was wrong")) {
		return false;
	}

	fixture.transport->Receive({ 1, 0 });
	Append(expected, ConnectRequest());
	if (!Expect(
			fixture.transport->sent() == expected
				&& fixture.observer.connectCount == 0,
			"contract: CONNECT request was wrong")) {
		return false;
	}

	fixture.transport->Receive(ConnectResponse());
	const auto proxy = rtc::SocketAddress(kProxyHost, kProxyPort);
	return Expect(
		fixture.observer.connectCount == 1
			&& fixture.observer.closeCount == 0
			&& fixture.socket->GetState() == rtc::Socket::CS_CONNECTED
			&& fixture.transport->connects()
				== std::vector<rtc::SocketAddress>{ proxy },
		"contract: tunnel connected without a proxy-only route");
}

[[nodiscard]] bool TestPartialWritesAndFragmentedResponses() {
	auto fixture = Fixture();
	fixture.transport->QueueSendLimit(1);
	fixture.transport->QueueWouldBlock();
	if (!Expect(fixture.Start(), "partial: Connect failed")) {
		return false;
	}
	fixture.transport->CompleteConnect();
	if (!Expect(
			fixture.transport->sent() == std::vector<uint8_t>{ 5 },
			"partial: greeting did not stop after one byte")) {
		return false;
	}
	fixture.transport->QueueSendLimit(1);
	fixture.transport->QueueWouldBlock();
	fixture.transport->NotifyWritable();
	if (!Expect(
			fixture.transport->sent() == std::vector<uint8_t>{ 5, 1 },
			"partial: second greeting fragment was wrong")) {
		return false;
	}
	fixture.transport->NotifyWritable();
	if (!Expect(
			fixture.transport->sent() == GreetingRequest(),
			"partial: greeting did not finish")) {
		return false;
	}

	fixture.transport->QueueSendLimit(3);
	fixture.transport->QueueWouldBlock();
	fixture.transport->Receive({ 5 });
	if (!Expect(
			fixture.transport->sent() == GreetingRequest(),
			"fragmented greeting advanced too early")) {
		return false;
	}
	fixture.transport->Receive({ 2 });
	auto expected = GreetingRequest();
	const auto authentication = AuthenticationRequest();
	expected.insert(
		expected.end(),
		authentication.begin(),
		authentication.begin() + 3);
	if (!Expect(
			fixture.transport->sent() == expected,
			"partial: authentication prefix was wrong")) {
		return false;
	}
	fixture.transport->NotifyWritable();
	expected = GreetingRequest();
	Append(expected, authentication);
	if (!Expect(
			fixture.transport->sent() == expected,
			"partial: authentication did not finish")) {
		return false;
	}

	fixture.transport->QueueSendLimit(2);
	fixture.transport->QueueWouldBlock();
	fixture.transport->Receive({ 1 });
	if (!Expect(
			fixture.transport->sent() == expected,
			"fragmented authentication advanced too early")) {
		return false;
	}
	fixture.transport->Receive({ 0 });
	const auto connect = ConnectRequest();
	expected.insert(expected.end(), connect.begin(), connect.begin() + 2);
	if (!Expect(
			fixture.transport->sent() == expected,
			"partial: CONNECT prefix was wrong")) {
		return false;
	}
	fixture.transport->NotifyWritable();
	expected = GreetingRequest();
	Append(expected, authentication);
	Append(expected, connect);
	if (!Expect(
			fixture.transport->sent() == expected,
			"partial: CONNECT did not finish")) {
		return false;
	}

	const auto response = ConnectResponse();
	for (auto i = size_t(); i != response.size(); ++i) {
		fixture.transport->Receive({ response[i] });
		const auto expectedConnects = (i + 1 == response.size()) ? 1 : 0;
		if (!Expect(
				fixture.observer.connectCount == expectedConnects,
				"fragmented CONNECT changed state at the wrong byte")) {
			return false;
		}
	}
	if (!Expect(
			fixture.observer.closeCount == 0
				&& fixture.socket->GetState() == rtc::Socket::CS_CONNECTED
				&& fixture.socket->GetRemoteAddress()
					== rtc::SocketAddress(kTargetHost, kTargetPort),
			"partial: completed tunnel state was wrong")) {
		return false;
	}
	fixture.transport->NotifyWritable();
	return Expect(
		fixture.observer.writeCount == 1,
		"partial: tunnel write readiness was not forwarded");
}

[[nodiscard]] bool TestReadWhileWritePending() {
	auto fixture = Fixture();
	fixture.transport->QueueWouldBlock();
	fixture.transport->SetSynchronousClose(ECONNABORTED);
	if (!Expect(fixture.Start(), "pending-read: Connect failed")) {
		return false;
	}
	fixture.transport->CompleteConnect();
	fixture.transport->Receive({ 5, 2 });
	fixture.transport->RemoteClose(ECONNABORTED);
	return Expect(
		fixture.transport->sent().empty()
			&& fixture.transport->closeCalls() == 1
			&& fixture.observer.connectCount == 0
			&& fixture.observer.closeCount == 1
			&& fixture.socket->GetState() == rtc::Socket::CS_CLOSED,
		"pending-read: fail-closed or exactly-once behavior was wrong");
}

[[nodiscard]] bool TestSendFailureClosesOnce() {
	auto fixture = Fixture();
	fixture.transport->QueueFailure(ECONNABORTED);
	fixture.transport->SetSynchronousClose(ECONNABORTED);
	if (!Expect(fixture.Start(), "send-failure: Connect failed")) {
		return false;
	}
	fixture.transport->CompleteConnect();
	fixture.transport->RemoteClose(ECONNABORTED);
	return Expect(
		fixture.transport->closeCalls() == 1
			&& fixture.observer.connectCount == 0
			&& fixture.observer.closeCount == 1,
		"send-failure: close was not emitted exactly once");
}

[[nodiscard]] bool TestMalformedResponses() {
	auto successWithResidual = ConnectResponse();
	successWithResidual.push_back(0x42);
	const auto cases = std::vector<MalformedCase>{
		{ "greeting version", HandshakePhase::Greeting, { 4, 2 } },
		{ "greeting method", HandshakePhase::Greeting, { 5, 0 } },
		{ "authentication version", HandshakePhase::Authentication, { 2, 0 } },
		{ "authentication status", HandshakePhase::Authentication, { 1, 1 } },
		{ "CONNECT version", HandshakePhase::Connect, { 4, 0, 0, 1 } },
		{ "CONNECT reply", HandshakePhase::Connect, { 5, 1, 0, 1 } },
		{ "CONNECT reserved", HandshakePhase::Connect, { 5, 0, 1, 1 } },
		{ "CONNECT address type", HandshakePhase::Connect, { 5, 0, 0, 2 } },
		{ "CONNECT empty domain", HandshakePhase::Connect, { 5, 0, 0, 3, 0 } },
		{ "CONNECT residual", HandshakePhase::Connect, successWithResidual },
	};
	for (const auto &test : cases) {
		auto fixture = Fixture();
		if (!Expect(ReachPhase(fixture, test.phase), test.name)) {
			return false;
		}
		fixture.transport->SetSynchronousClose(ECONNABORTED);
		fixture.transport->Receive(test.response);
		fixture.transport->RemoteClose(ECONNABORTED);
		if (!Expect(
				fixture.transport->closeCalls() == 1
					&& fixture.observer.connectCount == 0
					&& fixture.observer.closeCount == 1
					&& fixture.transport->connects().size() == 1
					&& fixture.socket->GetState() == rtc::Socket::CS_CLOSED,
				test.name)) {
			return false;
		}
	}
	return true;
}

[[nodiscard]] bool TestRemoteCloseEveryPhase() {
	const auto phases = std::vector<std::pair<HandshakePhase, const char *>>{
		{ HandshakePhase::Initial, "remote close in initial" },
		{ HandshakePhase::Greeting, "remote close in greeting" },
		{ HandshakePhase::Authentication, "remote close in authentication" },
		{ HandshakePhase::Connect, "remote close in CONNECT" },
		{ HandshakePhase::Tunnel, "remote close in tunnel" },
	};
	for (const auto &[phase, name] : phases) {
		auto fixture = Fixture();
		if (!Expect(ReachPhase(fixture, phase), name)) {
			return false;
		}
		const auto connectsBeforeClose = (phase == HandshakePhase::Tunnel) ? 1 : 0;
		fixture.transport->RemoteClose(ECONNABORTED);
		fixture.transport->RemoteClose(ECONNABORTED);
		if (!Expect(
				fixture.observer.connectCount == connectsBeforeClose
					&& fixture.observer.closeCount == 1
					&& fixture.observer.closeError == ECONNABORTED
					&& fixture.socket->GetState() == rtc::Socket::CS_CLOSED,
				name)) {
			return false;
		}
	}
	return true;
}

[[nodiscard]] bool TestLocalSynchronousClose() {
	auto fixture = Fixture();
	if (!Expect(
			ReachPhase(fixture, HandshakePhase::Authentication),
			"local close: could not reach authentication")) {
		return false;
	}
	fixture.transport->SetSynchronousClose(ECONNABORTED);
	const auto result = fixture.socket->Close();
	fixture.transport->RemoteClose(ECONNABORTED);
	return Expect(
		result == 0
			&& fixture.transport->closeCalls() == 1
			&& fixture.observer.connectCount == 0
			&& fixture.observer.closeCount == 0
			&& fixture.socket->GetState() == rtc::Socket::CS_CLOSED,
		"local close: synchronous close escaped terminal suppression");
}

} // namespace

int main() {
	using Test = std::pair<const char *, bool(*)()>;
	const auto tests = std::vector<Test>{
		{ "authenticated CONNECT contract", &TestAuthenticatedConnectContract },
		{ "partial writes and fragmented responses", &TestPartialWritesAndFragmentedResponses },
		{ "read while write pending", &TestReadWhileWritePending },
		{ "send failure", &TestSendFailureClosesOnce },
		{ "malformed responses", &TestMalformedResponses },
		{ "remote close", &TestRemoteCloseEveryPhase },
		{ "local synchronous close", &TestLocalSynchronousClose },
	};
	for (const auto &[name, test] : tests) {
		if (!test()) {
			std::fprintf(
				stderr,
				"SOCKS5 adapter test failed: %s\n",
				name);
			return 1;
		}
	}
	return 0;
}
