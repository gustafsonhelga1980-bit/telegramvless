/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/mtproto_proxy_data.h"

#include <rpl/producer.h>
#include <memory>

namespace Core {

enum class VlessError {
	None,
	InvalidProfile,
	SidecarNotFound,
	SidecarNotExecutable,
	SidecarNotTrusted,
	PortAllocationFailed,
	ConfigurationFailed,
	CallsActive,
	ProcessStartFailed,
	ProcessExited,
	ReadinessTimeout,
};

struct VlessStartResult final {
	MTP::ProxyData proxy;
	VlessError error = VlessError::None;

	[[nodiscard]] explicit operator bool() const {
		return error == VlessError::None;
	}
};

class VlessManager final {
public:
	using StartCallback = Fn<void(VlessStartResult)>;

	VlessManager();
	~VlessManager();

	VlessManager(const VlessManager &) = delete;
	VlessManager &operator=(const VlessManager &) = delete;

	void prepare(const QString &url, StartCallback done);
	[[nodiscard]] bool commit();
	void cancel();
	void stop();
	[[nodiscard]] bool running() const;
	[[nodiscard]] bool busy() const;
	[[nodiscard]] rpl::producer<VlessError> failures() const;

private:
	struct Private;
	const std::unique_ptr<Private> _private;
};

} // namespace Core
