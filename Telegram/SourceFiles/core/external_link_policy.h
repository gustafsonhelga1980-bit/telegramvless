/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include <memory>

class QString;

namespace Ui {
class Show;
} // namespace Ui

namespace Core::ExternalLinkPolicy {

[[nodiscard]] bool Protected();

void OpenUrl(
	const QString &url,
	std::shared_ptr<Ui::Show> show = nullptr);
void OpenEmailLink(
	const QString &email,
	std::shared_ptr<Ui::Show> show = nullptr);

} // namespace Core::ExternalLinkPolicy
