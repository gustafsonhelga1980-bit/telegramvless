/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "core/external_link_policy.h"

#include "base/algorithm.h"
#include "boxes/abstract_box.h"
#include "core/application.h"
#include "core/webview_network.h"
#include "lang/lang_keys.h"
#include "platform/platform_file_utilities.h"
#include "ui/boxes/confirm_box.h"
#include "ui/delayed_activation.h"
#include "ui/layers/show.h"
#include "ui/widgets/labels.h"

#include "styles/style_layers.h"

#include <QtCore/QPointer>
#include <QtCore/QUrl>
#include <QtGui/QClipboard>
#include <QtGui/QGuiApplication>

#include <memory>

namespace Core::ExternalLinkPolicy {
namespace {

enum class Type {
	Url,
	Email,
};

[[nodiscard]] QString EncodedForDisplay(const QString &value) {
	const auto parsed = QUrl(value, QUrl::TolerantMode);
	const auto encoded = parsed.toEncoded(QUrl::FullyEncoded);
	return !encoded.isEmpty() || value.isEmpty()
		? QString::fromUtf8(encoded)
		: QString::fromUtf8(QUrl::toPercentEncoding(
			value,
			":/?#[]@!$&'()*+,;="));
}

void UnsafeOpen(Type type, const QString &value) {
	Ui::PreventDelayedActivation();
	if (type == Type::Url) {
		Platform::File::UnsafeOpenUrl(value);
	} else {
		Platform::File::UnsafeOpenEmailLink(value);
	}
}

void ShowWarning(
		Type type,
		const QString &value,
		const QString &copied,
		const std::shared_ptr<Ui::Show> &show) {
	static QPointer<Ui::GenericBox> current;
	if (current
		|| (!(show && show->valid())
			&& !Core::App().activePrimaryWindow())) {
		return;
	}

	const auto displayed = EncodedForDisplay((type == Type::Email)
		? (value.startsWith(u"mailto:"_q, Qt::CaseInsensitive)
			? value
			: u"mailto:"_q + value)
		: value);
	const auto launchAvailable = std::make_shared<bool>(true);
	auto content = Box([=](not_null<Ui::GenericBox*> box) {
		current = box.get();
		Ui::ConfirmBox(box, {
			.text = tr::lng_external_link_warning_text(),
			.confirmed = [=](Fn<void()> hide) {
				QGuiApplication::clipboard()->setText(copied);
				hide();
			},
			.cancelled = [=](Fn<void()> hide) {
				hide();
				if (base::take(*launchAvailable)) {
					UnsafeOpen(type, value);
				}
			},
			.confirmText = tr::lng_external_link_copy(),
			.cancelText = tr::lng_external_link_open_outside(),
			.cancelStyle = &st::attentionBoxButton,
			.title = tr::lng_external_link_warning_title(),
			.strictCancel = true,
		});
		const auto &style = st::boxLabel;
		box->addSkip(style.style.lineHeight - st::boxPadding.bottom());
		const auto label = box->addRow(object_ptr<Ui::FlatLabel>(
			box,
			rpl::single(displayed),
			style));
		label->setSelectable(true);
		label->setContextCopyText(tr::lng_context_copy_link(tr::now));
	});
	if (show && show->valid()) {
		show->showBox(std::move(content), Ui::LayerOption::KeepOther);
	} else {
		Ui::show(std::move(content), Ui::LayerOption::KeepOther);
	}
}

void Open(
		Type type,
		const QString &value,
		const QString &copied,
		std::shared_ptr<Ui::Show> show) {
	if (!Protected()) {
		UnsafeOpen(type, value);
	} else {
		ShowWarning(type, value, copied, show);
	}
}

} // namespace

bool Protected() {
	return Core::IsAppLaunched()
		&& (Core::WebviewNetwork().mode != Webview::NetworkMode::System);
}

void OpenUrl(const QString &url, std::shared_ptr<Ui::Show> show) {
	Open(Type::Url, url, url, std::move(show));
}

void OpenEmailLink(const QString &email, std::shared_ptr<Ui::Show> show) {
	const auto value = email.startsWith(u"mailto:"_q, Qt::CaseInsensitive)
		? email.mid(7)
		: email;
	Open(Type::Email, value, email, std::move(show));
}

} // namespace Core::ExternalLinkPolicy
