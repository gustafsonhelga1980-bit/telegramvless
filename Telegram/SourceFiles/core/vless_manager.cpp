/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "core/vless_manager.h"

#include "base/random.h"
#include "base/weak_ptr.h"
#include "core/vless_profile.h"
#include "settings.h"

#include <QtCore/QCryptographicHash>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QPointer>
#include <QtCore/QProcess>
#include <QtCore/QProcessEnvironment>
#include <QtCore/QTimer>
#include <QtNetwork/QHostAddress>
#include <QtNetwork/QNetworkProxy>
#include <QtNetwork/QTcpServer>
#include <QtNetwork/QTcpSocket>

#include <rpl/event_stream.h>

#ifdef Q_OS_LINUX
#include <signal.h>
#include <sys/prctl.h>
#include <unistd.h>
#endif // Q_OS_LINUX

#include <utility>

namespace Core {
namespace {

constexpr auto kProcessStartTimeout = 3000;
constexpr auto kReadinessTimeout = 5000;
constexpr auto kReadinessStabilization = 250;
constexpr auto kProbeRetryDelay = 25;
constexpr auto kProbeSlice = 100;
constexpr auto kStopTimeout = 1500;
constexpr auto kExpectedXraySha256
	= "8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed";

[[nodiscard]] VlessStartResult Fail(VlessError error) {
	return { .error = error };
}

void Wipe(QString &value) {
	value.fill(QChar::Null);
	value.clear();
}

void Wipe(QByteArray &value) {
	value.fill('\0');
	value.clear();
}

void Wipe(MTP::ProxyData &proxy) {
	Wipe(proxy.user);
	Wipe(proxy.password);
	proxy = MTP::ProxyData();
}

[[nodiscard]] bool UnsafePermissions(const QFileInfo &info) {
	const auto permissions = info.permissions();
	return permissions.testFlag(QFileDevice::WriteGroup)
		|| permissions.testFlag(QFileDevice::WriteOther);
}

struct SidecarPath {
	QString executable;
	QString assets;
	VlessError error = VlessError::None;
};

struct PreparedStart {
	SidecarPath sidecar;
	QByteArray config;
	MTP::ProxyData proxy;
	VlessError error = VlessError::None;
};

void Wipe(PreparedStart &prepared) {
	Wipe(prepared.config);
	Wipe(prepared.proxy);
}

void ConfigureSidecarProcess(
		QProcess &process,
		const SidecarPath &sidecar,
		QStringList arguments) {
#ifdef Q_OS_LINUX
	const auto parentProcessId = ::getpid();
	process.setChildProcessModifier([parentProcessId] {
		if (::prctl(PR_SET_PDEATHSIG, SIGKILL) != 0
			|| ::getppid() != parentProcessId) {
			::_exit(127);
		}
	});
#endif // Q_OS_LINUX
	process.setProgram(sidecar.executable);
	process.setArguments(std::move(arguments));
	auto environment = QProcessEnvironment();
	environment.insert(u"XRAY_LOCATION_ASSET"_q, sidecar.assets);
	process.setProcessEnvironment(environment);
	process.setStandardOutputFile(QProcess::nullDevice());
	process.setStandardErrorFile(QProcess::nullDevice());
}

[[nodiscard]] SidecarPath ResolveSidecar() {
	const auto override = qEnvironmentVariable("TDESKTOP_XRAY_PATH");
	const auto requested = override.isEmpty()
		? (cExeDir() + u"xray/xray"_q)
		: override;
	const auto info = QFileInfo(requested);
	if (!info.exists() || !info.isFile()) {
		return { .error = VlessError::SidecarNotFound };
	} else if (!info.isExecutable()) {
		return { .error = VlessError::SidecarNotExecutable };
	}
	const auto canonical = info.canonicalFilePath();
	if (canonical.isEmpty()) {
		return { .error = VlessError::SidecarNotTrusted };
	}
	const auto canonicalInfo = QFileInfo(canonical);
	const auto parentInfo = QFileInfo(canonicalInfo.absolutePath());
	if (UnsafePermissions(canonicalInfo) || UnsafePermissions(parentInfo)) {
		return { .error = VlessError::SidecarNotTrusted };
	}

	auto file = QFile(canonical);
	if (!file.open(QIODevice::ReadOnly)) {
		return { .error = VlessError::SidecarNotTrusted };
	}
	auto hash = QCryptographicHash(QCryptographicHash::Sha256);
	if (!hash.addData(&file)
		|| hash.result().toHex() != QByteArray(kExpectedXraySha256)) {
		return { .error = VlessError::SidecarNotTrusted };
	}
	return {
		.executable = canonical,
		.assets = canonicalInfo.absolutePath(),
	};
}

[[nodiscard]] uint16 AllocateLoopbackPort() {
	auto server = QTcpServer();
	server.setProxy(QNetworkProxy::NoProxy);
	if (!server.listen(QHostAddress::LocalHost, 0)) {
		return 0;
	}
	const auto port = server.serverPort();
	server.close();
	return uint16(port);
}

[[nodiscard]] QString RandomCredential() {
	auto random = QByteArray(24, Qt::Uninitialized);
	base::RandomFill(random.data(), random.size());
	const auto encoded = random.toBase64(
		QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
	random.fill('\0');
	return QString::fromLatin1(encoded);
}

[[nodiscard]] PreparedStart PrepareStart(const QString &url) {
	const auto parsed = ParseVlessProfile(url);
	if (!parsed) {
		return { .error = VlessError::InvalidProfile };
	}
	const auto sidecar = ResolveSidecar();
	if (sidecar.error != VlessError::None) {
		return { .error = sidecar.error };
	}
	const auto port = AllocateLoopbackPort();
	if (!port) {
		return { .error = VlessError::PortAllocationFailed };
	}
	auto user = RandomCredential();
	auto password = RandomCredential();
	auto config = parsed.profile->xrayConfig(port, user, password);
	if (config.isEmpty()) {
		Wipe(user);
		Wipe(password);
		return { .error = VlessError::ConfigurationFailed };
	}
	return {
		.sidecar = sidecar,
		.config = std::move(config),
		.proxy = {
			.type = MTP::ProxyData::Type::Socks5,
			.host = u"127.0.0.1"_q,
			.port = port,
			.user = std::move(user),
			.password = std::move(password),
		},
	};
}

} // namespace

struct VlessManager::Private final
	: QObject
	, public base::has_weak_ptr {
	enum class Phase {
		Idle,
		Preparing,
		Testing,
		Starting,
		Probing,
		Stabilizing,
		Ready,
	};

	enum class ProbeStage {
		Greeting,
		Authentication,
		UdpAssociation,
	};

	~Private();

	void prepare(const QString &url, StartCallback done);
	void prepared(uint64 id, PreparedStart result);
	void startConfigurationTest(uint64 id);
	void configurationTestFinished(
		uint64 id,
		not_null<QProcess*> process,
		int exitCode,
		QProcess::ExitStatus exitStatus);
	void startCandidate(uint64 id);
	void candidateStarted(uint64 id, not_null<QProcess*> process);
	void candidateFinished(not_null<QProcess*> process);
	void beginProbe(uint64 id);
	void readProbe(uint64 id, uint64 probeId);
	void probeFailed(uint64 id, uint64 probeId);
	void probeSucceeded(uint64 id, uint64 probeId);
	void candidateReady(uint64 id);
	void failAttempt(VlessError error);
	void clearAttempt();
	void clearProbe();
	void stopProcess(QPointer<QProcess> process);
	void activeStopped(not_null<QProcess*> process);
	[[nodiscard]] bool attempt(uint64 id, Phase expected) const;
	[[nodiscard]] bool commit();
	void stop();

	Phase phase = Phase::Idle;
	ProbeStage probeStage = ProbeStage::Greeting;
	uint64 generation = 0;
	uint64 probeGeneration = 0;
	bool confirmationProbe = false;
	SidecarPath sidecar;
	QByteArray config;
	QByteArray probeReply;
	MTP::ProxyData candidateProxy;
	MTP::ProxyData activeProxy;
	QPointer<QProcess> testProcess;
	QPointer<QProcess> candidateProcess;
	QPointer<QProcess> activeProcess;
	QPointer<QTcpSocket> probeSocket;
	StartCallback callback;
	rpl::event_stream<VlessError> failures;
};

VlessManager::Private::~Private() {
	++generation;
	callback = nullptr;
	clearProbe();
	for (const auto process : findChildren<QProcess*>(
		QString(),
		Qt::FindDirectChildrenOnly)) {
		if (process->state() != QProcess::NotRunning) {
			process->kill();
		}
	}
	Wipe(config);
	Wipe(candidateProxy);
	Wipe(activeProxy);
}

bool VlessManager::Private::attempt(uint64 id, Phase expected) const {
	return generation == id && phase == expected;
}

void VlessManager::Private::prepare(
		const QString &url,
		StartCallback done) {
	if (phase != Phase::Idle) {
		done(Fail(VlessError::ConfigurationFailed));
		return;
	}
	phase = Phase::Preparing;
	callback = std::move(done);
	const auto id = ++generation;
	const auto guard = base::weak_ptr<Private>(this);
	crl::async([guard, id, url = QString(url)]() mutable {
		auto prepared = std::shared_ptr<PreparedStart>(
			new PreparedStart(PrepareStart(url)),
			[](PreparedStart *value) {
				Wipe(*value);
				delete value;
			});
		Wipe(url);
		crl::on_main(guard, [guard, id, prepared = std::move(prepared)] {
			guard->prepared(id, std::move(*prepared));
		});
	});
}

void VlessManager::Private::prepared(uint64 id, PreparedStart result) {
	if (!attempt(id, Phase::Preparing)) {
		Wipe(result.config);
		Wipe(result.proxy);
		return;
	} else if (result.error != VlessError::None) {
		failAttempt(result.error);
		return;
	}
	sidecar = std::move(result.sidecar);
	config = std::move(result.config);
	candidateProxy = std::move(result.proxy);
#ifdef TDESKTOP_VLESS_DEBUG_LOGS
	DEBUG_LOG(("VLESS Debug: sidecar configuration prepared."));
#endif // TDESKTOP_VLESS_DEBUG_LOGS
	startConfigurationTest(id);
}

void VlessManager::Private::startConfigurationTest(uint64 id) {
	phase = Phase::Testing;
	const auto process = new QProcess(this);
	testProcess = process;
	ConfigureSidecarProcess(*process, sidecar, {
		u"run"_q,
		u"-test"_q,
		u"-format"_q,
		u"json"_q,
		u"-c"_q,
		u"stdin:"_q,
	});
	QObject::connect(process, &QProcess::started, this, [=] {
		if (!attempt(id, Phase::Testing) || testProcess != process) {
			return;
		}
		if (process->write(config) != config.size()) {
			failAttempt(VlessError::ConfigurationFailed);
			return;
		}
		process->closeWriteChannel();
	});
	QObject::connect(
		process,
		&QProcess::finished,
		this,
		[=](int exitCode, QProcess::ExitStatus exitStatus) {
			configurationTestFinished(id, process, exitCode, exitStatus);
		});
	QObject::connect(
		process,
		&QProcess::errorOccurred,
		this,
		[=](QProcess::ProcessError) {
			if (attempt(id, Phase::Testing) && testProcess == process) {
				failAttempt(VlessError::ConfigurationFailed);
			}
		});
	process->start(QIODevice::ReadWrite);
	QTimer::singleShot(kProcessStartTimeout, this, [=] {
		if (attempt(id, Phase::Testing) && testProcess == process) {
			failAttempt(VlessError::ConfigurationFailed);
		}
	});
}

void VlessManager::Private::configurationTestFinished(
		uint64 id,
		not_null<QProcess*> process,
		int exitCode,
		QProcess::ExitStatus exitStatus) {
	if (!attempt(id, Phase::Testing) || testProcess.data() != process.get()) {
		return;
	}
	testProcess = nullptr;
	QObject::disconnect(process, nullptr, this, nullptr);
	process->deleteLater();
	if (exitStatus != QProcess::NormalExit || exitCode != 0) {
		failAttempt(VlessError::ConfigurationFailed);
		return;
	}
#ifdef TDESKTOP_VLESS_DEBUG_LOGS
	DEBUG_LOG(("VLESS Debug: sidecar configuration test passed."));
#endif // TDESKTOP_VLESS_DEBUG_LOGS
	startCandidate(id);
}

void VlessManager::Private::startCandidate(uint64 id) {
	phase = Phase::Starting;
	const auto process = new QProcess(this);
	candidateProcess = process;
	ConfigureSidecarProcess(
		*process,
		sidecar,
		{ u"run"_q, u"-c"_q, u"stdin:"_q });
	QObject::connect(process, &QProcess::started, this, [=] {
		candidateStarted(id, process);
	});
	QObject::connect(
		process,
		&QProcess::finished,
		this,
		[=](int, QProcess::ExitStatus) {
			candidateFinished(process);
		});
	QObject::connect(
		process,
		&QProcess::errorOccurred,
		this,
		[=](QProcess::ProcessError error) {
			if (candidateProcess == process) {
				if (phase == Phase::Starting
					&& error == QProcess::FailedToStart) {
					failAttempt(VlessError::ProcessStartFailed);
				} else if (process->state() == QProcess::NotRunning) {
					failAttempt(VlessError::ProcessExited);
				}
			} else if (activeProcess == process
				&& process->state() == QProcess::NotRunning) {
				activeStopped(process);
			}
		});
	process->start(QIODevice::ReadWrite);
	QTimer::singleShot(kProcessStartTimeout, this, [=] {
		if (attempt(id, Phase::Starting) && candidateProcess == process) {
			failAttempt(VlessError::ProcessStartFailed);
		}
	});
}

void VlessManager::Private::candidateStarted(
		uint64 id,
		not_null<QProcess*> process) {
	if (!attempt(id, Phase::Starting)
		|| candidateProcess.data() != process.get()) {
		return;
	}
	const auto size = config.size();
	const auto accepted = process->write(config);
	Wipe(config);
	if (accepted != size) {
		failAttempt(VlessError::ConfigurationFailed);
		return;
	}
	process->closeWriteChannel();
	phase = Phase::Probing;
#ifdef TDESKTOP_VLESS_DEBUG_LOGS
	DEBUG_LOG(("VLESS Debug: sidecar started; probing authenticated UDP."));
#endif // TDESKTOP_VLESS_DEBUG_LOGS
	QTimer::singleShot(kReadinessTimeout, this, [=] {
		if (generation == id
			&& phase != Phase::Idle
			&& phase != Phase::Ready) {
			failAttempt(VlessError::ReadinessTimeout);
		}
	});
	beginProbe(id);
}

void VlessManager::Private::candidateFinished(
		not_null<QProcess*> process) {
	if (candidateProcess.data() == process.get()) {
		failAttempt(VlessError::ProcessExited);
	} else if (activeProcess.data() == process.get()) {
		activeStopped(process);
	}
}

void VlessManager::Private::beginProbe(uint64 id) {
	if (!attempt(id, Phase::Probing)
		|| !candidateProcess
		|| candidateProcess->state() == QProcess::NotRunning) {
		if (generation == id && phase == Phase::Probing) {
			failAttempt(VlessError::ProcessExited);
		}
		return;
	}
	clearProbe();
	const auto probeId = ++probeGeneration;
	probeStage = ProbeStage::Greeting;
	probeReply.clear();
	const auto socket = new QTcpSocket(this);
	probeSocket = socket;
	socket->setProxy(QNetworkProxy::NoProxy);
	QObject::connect(socket, &QTcpSocket::connected, this, [=] {
		if (generation != id
			|| probeGeneration != probeId
			|| probeSocket != socket) {
			return;
		}
		const auto greeting = QByteArray::fromHex("050102");
		if (socket->write(greeting) != greeting.size()) {
			probeFailed(id, probeId);
		}
	});
	QObject::connect(socket, &QTcpSocket::readyRead, this, [=] {
		readProbe(id, probeId);
	});
	QObject::connect(
		socket,
		&QTcpSocket::errorOccurred,
		this,
		[=](QAbstractSocket::SocketError) {
			probeFailed(id, probeId);
		});
	socket->connectToHost(
		QHostAddress::LocalHost,
		candidateProxy.port);
	QTimer::singleShot(kProbeSlice, this, [=] {
		probeFailed(id, probeId);
	});
}

void VlessManager::Private::readProbe(uint64 id, uint64 probeId) {
	if (generation != id
		|| probeGeneration != probeId
		|| !probeSocket) {
		return;
	}
	probeReply += probeSocket->readAll();
	if (probeStage == ProbeStage::UdpAssociation) {
		if (probeReply.size() < 4) {
			return;
		}
		if (probeReply[0] != char(5)
			|| probeReply[1] != char(0)
			|| probeReply[2] != char(0)
			|| probeReply[3] != char(1)) {
			probeFailed(id, probeId);
			return;
		}
		constexpr auto expected = 10;
		if (probeReply.size() < expected) {
			return;
		} else if (probeReply.size() != expected) {
			probeFailed(id, probeId);
			return;
		}
		const auto proxyAddress = QHostAddress(candidateProxy.host);
		const auto relayAddress = (uint32(uchar(probeReply[4])) << 24)
			| (uint32(uchar(probeReply[5])) << 16)
			| (uint32(uchar(probeReply[6])) << 8)
			| uint32(uchar(probeReply[7]));
		if (proxyAddress.protocol() != QAbstractSocket::IPv4Protocol
			|| !proxyAddress.isLoopback()
			|| (relayAddress != 0 && (relayAddress >> 24) != 127)) {
			probeFailed(id, probeId);
			return;
		}
		const auto port = (uint16(uchar(probeReply[expected - 2])) << 8)
			| uint16(uchar(probeReply[expected - 1]));
		if (!port) {
			probeFailed(id, probeId);
			return;
		}
#ifdef TDESKTOP_VLESS_DEBUG_LOGS
		DEBUG_LOG((
			"VLESS Debug: authenticated SOCKS5 UDP association succeeded."));
#endif // TDESKTOP_VLESS_DEBUG_LOGS
		probeSucceeded(id, probeId);
		return;
	}
	if (probeReply.size() < 2) {
		return;
	}
	const auto response = probeReply.left(2);
	probeReply.remove(0, 2);
	if (!probeReply.isEmpty()) {
		probeFailed(id, probeId);
		return;
	}
	if (probeStage == ProbeStage::Greeting) {
		if (response != QByteArray::fromHex("0502")) {
			probeFailed(id, probeId);
			return;
		}
		auto user = candidateProxy.user.toUtf8();
		auto password = candidateProxy.password.toUtf8();
		auto request = QByteArray();
		request.reserve(3 + user.size() + password.size());
		request.push_back(char(1));
		request.push_back(char(user.size()));
		request += user;
		request.push_back(char(password.size()));
		request += password;
		probeStage = ProbeStage::Authentication;
		const auto accepted = probeSocket->write(request);
		Wipe(user);
		Wipe(password);
		const auto size = request.size();
		Wipe(request);
		if (accepted != size) {
			probeFailed(id, probeId);
		}
	} else if (response[0] == char(1) && response[1] == char(0)) {
		const auto request = QByteArray::fromHex("05030001000000000000");
		probeStage = ProbeStage::UdpAssociation;
		if (probeSocket->write(request) != request.size()) {
			probeFailed(id, probeId);
		}
	} else {
		probeFailed(id, probeId);
	}
}

void VlessManager::Private::probeFailed(uint64 id, uint64 probeId) {
	if (generation != id
		|| phase != Phase::Probing
		|| probeGeneration != probeId) {
		return;
	}
	clearProbe();
	confirmationProbe = false;
	QTimer::singleShot(kProbeRetryDelay, this, [=] {
		beginProbe(id);
	});
}

void VlessManager::Private::probeSucceeded(uint64 id, uint64 probeId) {
	if (generation != id
		|| phase != Phase::Probing
		|| probeGeneration != probeId) {
		return;
	}
	clearProbe();
	if (confirmationProbe) {
		candidateReady(id);
		return;
	}
	phase = Phase::Stabilizing;
	QTimer::singleShot(kReadinessStabilization, this, [=] {
		if (!attempt(id, Phase::Stabilizing)) {
			return;
		} else if (!candidateProcess
			|| candidateProcess->state() == QProcess::NotRunning) {
			failAttempt(VlessError::ProcessExited);
			return;
		}
		confirmationProbe = true;
		phase = Phase::Probing;
		beginProbe(id);
	});
}

void VlessManager::Private::candidateReady(uint64 id) {
	if (!attempt(id, Phase::Probing)
		|| !candidateProcess
		|| candidateProcess->state() == QProcess::NotRunning) {
		failAttempt(VlessError::ProcessExited);
		return;
	}
	phase = Phase::Ready;
	confirmationProbe = false;
#ifdef TDESKTOP_VLESS_DEBUG_LOGS
	DEBUG_LOG((
		"VLESS Debug: authenticated UDP readiness remained stable."));
#endif // TDESKTOP_VLESS_DEBUG_LOGS
	const auto done = std::move(callback);
	if (done) {
		done({ .proxy = candidateProxy });
	}
}

void VlessManager::Private::clearProbe() {
	++probeGeneration;
	probeReply.fill('\0');
	probeReply.clear();
	if (const auto socket = probeSocket) {
		probeSocket = nullptr;
		QObject::disconnect(socket, nullptr, this, nullptr);
		socket->abort();
		socket->deleteLater();
	}
}

void VlessManager::Private::stopProcess(QPointer<QProcess> process) {
	if (!process) {
		return;
	}
	QObject::disconnect(process, nullptr, this, nullptr);
	if (process->state() == QProcess::NotRunning) {
		process->deleteLater();
		return;
	}
	QObject::connect(
		process,
		&QProcess::finished,
		process,
		[=] { process->deleteLater(); });
	process->terminate();
	QTimer::singleShot(kStopTimeout, process, [=] {
		if (process->state() != QProcess::NotRunning) {
			process->kill();
		}
	});
}

void VlessManager::Private::clearAttempt() {
	clearProbe();
	const auto test = testProcess;
	const auto candidate = candidateProcess;
	testProcess = nullptr;
	candidateProcess = nullptr;
	stopProcess(test);
	stopProcess(candidate);
	Wipe(config);
	Wipe(candidateProxy);
	sidecar = SidecarPath();
	confirmationProbe = false;
	phase = Phase::Idle;
}

void VlessManager::Private::failAttempt(VlessError error) {
	if (phase == Phase::Idle) {
		return;
	}
#ifdef TDESKTOP_VLESS_DEBUG_LOGS
	DEBUG_LOG((
		"VLESS Debug: startup failed with error %1 in phase %2, "
		"probe stage %3."
	).arg(int(error)
	).arg(int(phase)
	).arg(int(probeStage)));
#endif // TDESKTOP_VLESS_DEBUG_LOGS
	++generation;
	const auto done = std::move(callback);
	clearAttempt();
	if (done) {
		done(Fail(error));
	}
}

bool VlessManager::Private::commit() {
	if (phase != Phase::Ready
		|| !candidateProcess
		|| candidateProcess->state() == QProcess::NotRunning) {
		if (phase != Phase::Idle) {
			failAttempt(VlessError::ProcessExited);
		}
		return false;
	}
	const auto previous = activeProcess;
	activeProcess = candidateProcess;
	activeProxy = candidateProxy;
	candidateProcess = nullptr;
	Wipe(candidateProxy);
	Wipe(config);
	sidecar = SidecarPath();
	confirmationProbe = false;
	phase = Phase::Idle;
	++generation;
	stopProcess(previous);
	return true;
}

void VlessManager::Private::activeStopped(
		not_null<QProcess*> process) {
	if (activeProcess.data() != process.get()) {
		return;
	}
	activeProcess = nullptr;
	QObject::disconnect(process, nullptr, this, nullptr);
	process->deleteLater();
	Wipe(activeProxy);
#ifdef TDESKTOP_VLESS_DEBUG_LOGS
	DEBUG_LOG(("VLESS Debug: active sidecar stopped."));
#endif // TDESKTOP_VLESS_DEBUG_LOGS
	failures.fire(VlessError::ProcessExited);
}

void VlessManager::Private::stop() {
	if (phase != Phase::Idle) {
		failAttempt(VlessError::ProcessExited);
	}
	const auto process = activeProcess;
	activeProcess = nullptr;
	Wipe(activeProxy);
	stopProcess(process);
}

VlessManager::VlessManager()
: _private(std::make_unique<Private>()) {
}

VlessManager::~VlessManager() = default;

void VlessManager::prepare(const QString &url, StartCallback done) {
	_private->prepare(url, std::move(done));
}

bool VlessManager::commit() {
	return _private->commit();
}

void VlessManager::cancel() {
	_private->failAttempt(VlessError::ConfigurationFailed);
}

void VlessManager::stop() {
	_private->stop();
}

bool VlessManager::running() const {
	return _private->activeProcess
		&& _private->activeProcess->state() != QProcess::NotRunning;
}

bool VlessManager::busy() const {
	return _private->phase != Private::Phase::Idle;
}

rpl::producer<VlessError> VlessManager::failures() const {
	return _private->failures.events();
}

} // namespace Core
