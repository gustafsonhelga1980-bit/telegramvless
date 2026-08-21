/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "core/vless_profile.h"

#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QJsonParseError>
#include <QtCore/QMap>
#include <QtCore/QSet>
#include <QtCore/QUrl>

#include <algorithm>
#include <initializer_list>
#include <utility>

namespace Core {
namespace {

constexpr auto kMaxProfileBytes = 8192;
constexpr auto kMaxQueryFields = 32;
constexpr auto kMaxEmbeddedJsonBytes = 4096;
constexpr auto kMaxJsonDepth = 8;
constexpr auto kMaxJsonItems = 128;
constexpr auto kMaxSocksCredentialBytes = 255;
constexpr auto kMaxXhttpPaddingBytes = 64 * 1024;
constexpr auto kMaxXhttpUploadBytes = 16 * 1024 * 1024;
constexpr auto kMaxXhttpBufferedPosts = 1024;
constexpr auto kMaxXhttpHeaderBytes = 1024 * 1024;
constexpr auto kMaxXhttpConnections = 64;

[[nodiscard]] VlessProfileResult Fail(VlessProfileError error) {
	return {
		.profile = std::nullopt,
		.error = error,
	};
}

[[nodiscard]] int HexValue(char value) {
	if (value >= '0' && value <= '9') {
		return value - '0';
	} else if (value >= 'a' && value <= 'f') {
		return value - 'a' + 10;
	} else if (value >= 'A' && value <= 'F') {
		return value - 'A' + 10;
	}
	return -1;
}

[[nodiscard]] std::optional<QString> PercentDecode(
		const QByteArray &encoded) {
	auto bytes = QByteArray();
	bytes.reserve(encoded.size());
	for (auto i = 0; i != encoded.size(); ++i) {
		const auto value = encoded[i];
		if (value == '%') {
			if (i + 2 >= encoded.size()) {
				return std::nullopt;
			}
			const auto high = HexValue(encoded[i + 1]);
			const auto low = HexValue(encoded[i + 2]);
			if (high < 0 || low < 0) {
				return std::nullopt;
			}
			bytes.push_back(char((high << 4) | low));
			i += 2;
		} else {
			bytes.push_back(value);
		}
	}
	const auto result = QString::fromUtf8(bytes);
	if (result.toUtf8() != bytes) {
		return std::nullopt;
	}
	return result;
}

[[nodiscard]] bool IsCanonicalUuid(const QString &value) {
	if (value.size() != 36) {
		return false;
	}
	for (auto i = 0; i != value.size(); ++i) {
		if (i == 8 || i == 13 || i == 18 || i == 23) {
			if (value[i] != '-') {
				return false;
			}
		} else if (value[i].unicode() > 0x7F
			|| HexValue(char(value[i].unicode())) < 0) {
			return false;
		}
	}
	return true;
}

[[nodiscard]] bool ContainsSpace(const QString &value) {
	for (const auto character : value) {
		if (character.isSpace()) {
			return true;
		}
	}
	return false;
}

[[nodiscard]] bool ContainsRawControl(const QString &value) {
	for (const auto character : value) {
		const auto code = character.unicode();
		if (code <= 0x1F || code == 0x7F) {
			return true;
		}
	}
	return false;
}

[[nodiscard]] bool IsOneOf(
		const QString &value,
		std::initializer_list<QString> values) {
	return std::find(values.begin(), values.end(), value) != values.end();
}

[[nodiscard]] bool IsSafeString(
		const QString &value,
		int maximumBytes = kMaxProfileBytes) {
	const auto encoded = value.toUtf8();
	return !ContainsRawControl(value)
		&& encoded.size() <= maximumBytes
		&& QString::fromUtf8(encoded) == value;
}

[[nodiscard]] bool IsServerNameValid(const QString &value) {
	return !value.isEmpty()
		&& !ContainsSpace(value)
		&& IsSafeString(value, 255);
}

[[nodiscard]] bool IsFingerprintSupported(const QString &value) {
	return IsOneOf(value, {
		u"chrome"_q,
		u"firefox"_q,
		u"safari"_q,
		u"ios"_q,
		u"android"_q,
		u"edge"_q,
		u"360"_q,
		u"qq"_q,
		u"random"_q,
		u"randomized"_q,
		u"randomizednoalpn"_q,
	});
}

[[nodiscard]] std::optional<QByteArray> DecodeBase64Url(
		const QString &value) {
	for (const auto character : value) {
		const auto code = character.unicode();
		if (!((code >= 'A' && code <= 'Z')
			|| (code >= 'a' && code <= 'z')
			|| (code >= '0' && code <= '9')
			|| code == '_'
			|| code == '-')) {
			return std::nullopt;
		}
	}
	auto encoded = value.toLatin1();
	while ((encoded.size() % 4) != 0) {
		encoded.push_back('=');
	}
	const auto decoded = QByteArray::fromBase64Encoding(
		std::move(encoded),
		QByteArray::Base64UrlEncoding
			| QByteArray::AbortOnBase64DecodingErrors);
	return decoded ? std::optional<QByteArray>(*decoded) : std::nullopt;
}

[[nodiscard]] bool IsPublicKeyValid(const QString &value) {
	const auto decoded = DecodeBase64Url(value);
	return decoded && decoded->size() == 32;
}

[[nodiscard]] bool IsMldsa65VerifyValid(const QString &value) {
	const auto decoded = DecodeBase64Url(value);
	return decoded && decoded->size() == 1952;
}

[[nodiscard]] bool IsShortIdValid(const QString &value) {
	if (value.size() > 16 || (value.size() % 2) != 0) {
		return false;
	}
	for (const auto character : value) {
		if (character.unicode() > 0x7F
			|| HexValue(char(character.unicode())) < 0) {
			return false;
		}
	}
	return true;
}

[[nodiscard]] bool IsUnsignedDecimal(const QString &value) {
	if (value.isEmpty()) {
		return false;
	}
	for (const auto character : value) {
		if (character < '0' || character > '9') {
			return false;
		}
	}
	return true;
}

[[nodiscard]] std::optional<int> ParseBoundedInteger(
		const QString &value,
		int minimum,
		int maximum) {
	if (!IsUnsignedDecimal(value)) {
		return std::nullopt;
	}
	auto ok = false;
	const auto result = value.toInt(&ok);
	return (ok && result >= minimum && result <= maximum)
		? std::optional<int>(result)
		: std::nullopt;
}

[[nodiscard]] bool IsMlkemEncryptionValid(const QString &value) {
	const auto fields = value.split('.', Qt::KeepEmptyParts);
	if (fields.size() < 4
		|| fields[0] != u"mlkem768x25519plus"_q
		|| !IsOneOf(fields[1], {
			u"native"_q,
			u"xorpub"_q,
			u"random"_q,
		})
		|| !IsOneOf(fields[2], { u"1rtt"_q, u"0rtt"_q })) {
		return false;
	}

	auto firstKey = fields.size();
	for (auto i = 3; i != fields.size(); ++i) {
		const auto decoded = DecodeBase64Url(fields[i]);
		if (decoded && (decoded->size() == 32 || decoded->size() == 1184)) {
			firstKey = i;
			break;
		}
	}
	if (firstKey == fields.size()) {
		return false;
	}
	for (auto i = firstKey; i != fields.size(); ++i) {
		const auto decoded = DecodeBase64Url(fields[i]);
		if (!decoded || (decoded->size() != 32 && decoded->size() != 1184)) {
			return false;
		}
	}

	auto encodedPaddingBytes = 0;
	for (auto i = 3; i != firstKey; ++i) {
		const auto fieldBytes = fields[i].toUtf8();
		if (fieldBytes.isEmpty()
			|| fieldBytes.size() >= 20
			|| !IsSafeString(fields[i], 19)) {
			return false;
		}
		encodedPaddingBytes += fieldBytes.size() + 1;
		if (encodedPaddingBytes > 1024) {
			return false;
		}
	}
	return true;
}

[[nodiscard]] std::optional<QStringList> ParseAlpn(const QString &value) {
	if (value.isEmpty()) {
		return std::nullopt;
	}
	const auto fields = value.split(',', Qt::KeepEmptyParts);
	if (fields.size() > 8) {
		return std::nullopt;
	}
	for (const auto &field : fields) {
		const auto encoded = field.toUtf8();
		if (field.isEmpty()
			|| ContainsSpace(field)
			|| !IsSafeString(field, 255)
			|| encoded.size() > 255) {
			return std::nullopt;
		}
	}
	return fields;
}

[[nodiscard]] bool IsCertificatePinListValid(const QString &value) {
	if (value.isEmpty()) {
		return true;
	}
	const auto fields = value.split(',', Qt::KeepEmptyParts);
	if (fields.size() > 16) {
		return false;
	}
	for (auto field : fields) {
		field.remove(':');
		if (field.size() != 64) {
			return false;
		}
		for (const auto character : field) {
			if (character.unicode() > 0x7F
				|| HexValue(char(character.unicode())) < 0) {
				return false;
			}
		}
	}
	return true;
}

[[nodiscard]] bool IsVerifyNameListValid(const QString &value) {
	if (value.isEmpty()) {
		return true;
	}
	const auto fields = value.split(',', Qt::KeepEmptyParts);
	if (fields.size() > 16) {
		return false;
	}
	for (const auto &field : fields) {
		if (!IsServerNameValid(field)) {
			return false;
		}
	}
	return true;
}

[[nodiscard]] bool IsEchValid(const QString &value) {
	if (value.isEmpty()) {
		return true;
	} else if (value.contains(u"://"_q)) {
		const auto fields = value.split('+', Qt::KeepEmptyParts);
		if (fields.size() > 2) {
			return false;
		}
		const auto server = fields.back();
		if (fields.size() == 2 && !IsServerNameValid(fields.front())) {
			return false;
		}
		const auto url = QUrl(server, QUrl::StrictMode);
		if (!url.isValid()
			|| (!server.startsWith(u"https://"_q)
				&& !server.startsWith(u"h2c://"_q)
				&& !server.startsWith(u"udp://"_q))
			|| url.host().isEmpty()
			|| !url.userName().isEmpty()
			|| !url.password().isEmpty()
			|| !url.fragment().isEmpty()
			|| url.port(-1) == 0
			|| url.port(-1) > 65535) {
			return false;
		}
		return url.scheme() != u"udp"_q
			|| (url.path().isEmpty() && !url.hasQuery());
	}
	auto encoded = value.toLatin1();
	if (QString::fromLatin1(encoded) != value
		|| (encoded.size() % 4) != 0) {
		return false;
	}
	const auto decoded = QByteArray::fromBase64Encoding(
		std::move(encoded),
		QByteArray::Base64Encoding
			| QByteArray::AbortOnBase64DecodingErrors);
	return bool(decoded) && !(*decoded).isEmpty();
}

class JsonScanner final {
public:
	explicit JsonScanner(const QByteArray &data);

	[[nodiscard]] bool scan();

private:
	void skipWhitespace();
	[[nodiscard]] bool scanValue(int depth);
	[[nodiscard]] bool scanObject(int depth);
	[[nodiscard]] bool scanArray(int depth);
	[[nodiscard]] bool scanString(QString *result);
	[[nodiscard]] bool scanScalar();

	const QByteArray &_data;
	int _position = 0;

};

JsonScanner::JsonScanner(const QByteArray &data)
: _data(data) {
}

bool JsonScanner::scan() {
	skipWhitespace();
	if (!scanValue(0)) {
		return false;
	}
	skipWhitespace();
	return _position == _data.size();
}

void JsonScanner::skipWhitespace() {
	while (_position != _data.size()) {
		const auto value = _data[_position];
		if (value != ' '
			&& value != '\t'
			&& value != '\r'
			&& value != '\n') {
			break;
		}
		++_position;
	}
}

bool JsonScanner::scanValue(int depth) {
	if (depth > kMaxJsonDepth || _position == _data.size()) {
		return false;
	}
	switch (_data[_position]) {
	case '{': return scanObject(depth + 1);
	case '[': return scanArray(depth + 1);
	case '"': return scanString(nullptr);
	default: return scanScalar();
	}
}

bool JsonScanner::scanObject(int depth) {
	++_position;
	skipWhitespace();
	if (_position != _data.size() && _data[_position] == '}') {
		++_position;
		return true;
	}
	auto keys = QSet<QString>();
	while (_position != _data.size()) {
		auto key = QString();
		if (keys.size() >= kMaxJsonItems || !scanString(&key)) {
			return false;
		}
		if (keys.contains(key)) {
			return false;
		}
		keys.insert(key);
		skipWhitespace();
		if (_position == _data.size() || _data[_position++] != ':') {
			return false;
		}
		skipWhitespace();
		if (!scanValue(depth)) {
			return false;
		}
		skipWhitespace();
		if (_position == _data.size()) {
			return false;
		}
		const auto delimiter = _data[_position++];
		if (delimiter == '}') {
			return true;
		} else if (delimiter != ',') {
			return false;
		}
		skipWhitespace();
	}
	return false;
}

bool JsonScanner::scanArray(int depth) {
	++_position;
	skipWhitespace();
	if (_position != _data.size() && _data[_position] == ']') {
		++_position;
		return true;
	}
	auto count = 0;
	while (_position != _data.size()) {
		if (++count > kMaxJsonItems || !scanValue(depth)) {
			return false;
		}
		skipWhitespace();
		if (_position == _data.size()) {
			return false;
		}
		const auto delimiter = _data[_position++];
		if (delimiter == ']') {
			return true;
		} else if (delimiter != ',') {
			return false;
		}
		skipWhitespace();
	}
	return false;
}

bool JsonScanner::scanString(QString *result) {
	if (_position == _data.size() || _data[_position] != '"') {
		return false;
	}
	const auto start = _position++;
	while (_position != _data.size()) {
		const auto value = uchar(_data[_position++]);
		if (value == '"') {
			if (result) {
				const auto token = _data.mid(start, _position - start);
				QJsonParseError error;
				const auto decoded = QJsonDocument::fromJson(
					QByteArray("[") + token + QByteArray("]"),
					&error);
				if (error.error != QJsonParseError::NoError
					|| !decoded.isArray()
					|| decoded.array().size() != 1
					|| !decoded.array().at(0).isString()) {
					return false;
				}
				*result = decoded.array().at(0).toString();
			}
			return true;
		} else if (value == '\\') {
			if (_position == _data.size()) {
				return false;
			}
			const auto escaped = _data[_position++];
			if (escaped == 'u') {
				if (_position + 4 > _data.size()) {
					return false;
				}
				for (auto i = 0; i != 4; ++i) {
					if (HexValue(_data[_position + i]) < 0) {
						return false;
					}
				}
				_position += 4;
			}
		} else if (value < 0x20) {
			return false;
		}
	}
	return false;
}

bool JsonScanner::scanScalar() {
	const auto start = _position;
	while (_position != _data.size()) {
		const auto value = _data[_position];
		if (value == ','
			|| value == ']'
			|| value == '}'
			|| value == ' '
			|| value == '\t'
			|| value == '\r'
			|| value == '\n') {
			break;
		}
		++_position;
	}
	return _position != start;
}

[[nodiscard]] bool IsJsonValueSafe(const QJsonValue &value, int depth) {
	if (depth > kMaxJsonDepth) {
		return false;
	} else if (value.isString()) {
		return IsSafeString(value.toString(), kMaxEmbeddedJsonBytes);
	} else if (value.isArray()) {
		const auto array = value.toArray();
		if (array.size() > kMaxJsonItems) {
			return false;
		}
		for (const auto &entry : array) {
			if (!IsJsonValueSafe(entry, depth + 1)) {
				return false;
			}
		}
	} else if (value.isObject()) {
		const auto object = value.toObject();
		if (object.size() > kMaxJsonItems) {
			return false;
		}
		for (auto i = object.constBegin(); i != object.constEnd(); ++i) {
			if (!IsSafeString(i.key(), 256)
				|| !IsJsonValueSafe(i.value(), depth + 1)) {
				return false;
			}
		}
	}
	return true;
}

[[nodiscard]] std::optional<QJsonObject> ParseJsonObject(
		const QString &value) {
	const auto encoded = value.toUtf8();
	if (encoded.isEmpty()
		|| encoded.size() > kMaxEmbeddedJsonBytes
		|| !JsonScanner(encoded).scan()) {
		return std::nullopt;
	}
	QJsonParseError error;
	const auto document = QJsonDocument::fromJson(encoded, &error);
	if (error.error != QJsonParseError::NoError
		|| !document.isObject()
		|| !IsJsonValueSafe(document.object(), 0)) {
		return std::nullopt;
	}
	return document.object();
}

[[nodiscard]] bool HasOnlyKeys(
		const QJsonObject &object,
		const QStringList &allowed) {
	for (auto i = object.constBegin(); i != object.constEnd(); ++i) {
		if (!allowed.contains(i.key())) {
			return false;
		}
	}
	return true;
}

[[nodiscard]] std::optional<qint64> JsonInteger(
		const QJsonValue &value,
		qint64 minimum,
		qint64 maximum) {
	if (!value.isDouble()) {
		return std::nullopt;
	}
	const auto number = value.toDouble();
	if (number < double(minimum) || number > double(maximum)) {
		return std::nullopt;
	}
	const auto integer = qint64(number);
	return (double(integer) == number
		&& integer >= minimum
		&& integer <= maximum)
		? std::optional<qint64>(integer)
		: std::nullopt;
}

[[nodiscard]] std::optional<std::pair<qint64, qint64>> JsonRange(
		const QJsonValue &value,
		qint64 minimum,
		qint64 maximum) {
	if (const auto integer = JsonInteger(value, minimum, maximum)) {
		return std::pair<qint64, qint64>(*integer, *integer);
	} else if (!value.isString()) {
		return std::nullopt;
	}
	const auto fields = value.toString().split('-', Qt::KeepEmptyParts);
	if (fields.size() != 2
		|| !IsUnsignedDecimal(fields[0])
		|| !IsUnsignedDecimal(fields[1])) {
		return std::nullopt;
	}
	auto leftOk = false;
	auto rightOk = false;
	const auto left = fields[0].toLongLong(&leftOk);
	const auto right = fields[1].toLongLong(&rightOk);
	if (!leftOk
		|| !rightOk
		|| left < minimum
		|| left > maximum
		|| right < minimum
		|| right > maximum
		|| left > right) {
		return std::nullopt;
	}
	return std::pair<qint64, qint64>(left, right);
}

[[nodiscard]] bool IsJsonString(
		const QJsonValue &value,
		bool allowEmpty = true,
		int maximumBytes = 1024) {
	return value.isString()
		&& (allowEmpty || !value.toString().isEmpty())
		&& IsSafeString(value.toString(), maximumBytes);
}

[[nodiscard]] bool IsSudokuPattern(QString value) {
	value = value.trimmed().toLower();
	value.remove(' ');
	if (value.isEmpty()) {
		return true;
	} else if (value.size() != 8) {
		return false;
	}
	return value.count('x') == 2
		&& value.count('p') == 2
		&& value.count('v') == 4
		&& value.count('x') + value.count('p') + value.count('v') == 8;
}

[[nodiscard]] bool IsSudokuPatternArray(const QJsonValue &value) {
	if (!value.isArray() || value.toArray().size() > 32) {
		return false;
	}
	for (const auto &entry : value.toArray()) {
		if (!entry.isString() || !IsSudokuPattern(entry.toString())) {
			return false;
		}
	}
	return true;
}

[[nodiscard]] bool IsHttpToken(const QString &value, bool allowEmpty = false) {
	if (value.isEmpty()) {
		return allowEmpty;
	}
	for (const auto character : value) {
		const auto code = character.unicode();
		if ((code >= '0' && code <= '9')
			|| (code >= 'A' && code <= 'Z')
			|| (code >= 'a' && code <= 'z')) {
			continue;
		}
		switch (code) {
		case '!':
		case '#':
		case '$':
		case '%':
		case '&':
		case '\'':
		case '*':
		case '+':
		case '-':
		case '.':
		case '^':
		case '_':
		case '`':
		case '|':
		case '~': continue;
		default: return false;
		}
	}
	return true;
}

[[nodiscard]] bool IsHeadersObject(const QJsonValue &value) {
	if (!value.isObject() || value.toObject().size() > 32) {
		return false;
	}
	const auto object = value.toObject();
	for (auto i = object.constBegin(); i != object.constEnd(); ++i) {
		if (i.key().compare(u"host"_q, Qt::CaseInsensitive) == 0
			|| !IsHttpToken(i.key())
			|| !IsJsonString(i.value(), true, 2048)) {
			return false;
		}
	}
	return true;
}

[[nodiscard]] bool ValidateXmux(const QJsonValue &value) {
	if (!value.isObject()) {
		return false;
	}
	const auto object = value.toObject();
	if (!HasOnlyKeys(object, {
		u"maxConcurrency"_q,
		u"maxConnections"_q,
		u"cMaxReuseTimes"_q,
		u"hMaxRequestTimes"_q,
		u"hMaxReusableSecs"_q,
		u"hKeepAlivePeriod"_q,
	})) {
		return false;
	}
	for (const auto &key : { u"maxConcurrency"_q, u"maxConnections"_q }) {
		if (object.contains(key)
			&& !JsonRange(object.value(key), 0, kMaxXhttpConnections)) {
			return false;
		}
	}
	for (const auto &key : { u"cMaxReuseTimes"_q, u"hMaxRequestTimes"_q }) {
		if (object.contains(key)
			&& !JsonRange(object.value(key), 0, 1000000)) {
			return false;
		}
	}
	if (object.contains(u"hMaxReusableSecs"_q)
		&& !JsonRange(object.value(u"hMaxReusableSecs"_q), 0, 86400)) {
		return false;
	}
	if (object.contains(u"hKeepAlivePeriod"_q)
		&& !JsonInteger(
			object.value(u"hKeepAlivePeriod"_q),
			0,
			86400)) {
		return false;
	}
	const auto concurrency = object.contains(u"maxConcurrency"_q)
		? JsonRange(object.value(u"maxConcurrency"_q), 0, 1000000)
		: std::optional<std::pair<qint64, qint64>>();
	const auto connections = object.contains(u"maxConnections"_q)
		? JsonRange(object.value(u"maxConnections"_q), 0, 1000000)
		: std::optional<std::pair<qint64, qint64>>();
	return !(concurrency
		&& connections
		&& std::max(concurrency->first, concurrency->second) > 0
		&& std::max(connections->first, connections->second) > 0);
}

[[nodiscard]] bool ValidateXhttpExtra(
		const QJsonObject &object,
		const QString &mode) {
	if (!HasOnlyKeys(object, {
		u"headers"_q,
		u"xPaddingBytes"_q,
		u"xPaddingObfsMode"_q,
		u"xPaddingKey"_q,
		u"xPaddingHeader"_q,
		u"xPaddingPlacement"_q,
		u"xPaddingMethod"_q,
		u"uplinkHTTPMethod"_q,
		u"sessionPlacement"_q,
		u"sessionKey"_q,
		u"seqPlacement"_q,
		u"seqKey"_q,
		u"uplinkDataPlacement"_q,
		u"uplinkDataKey"_q,
		u"uplinkChunkSize"_q,
		u"noGRPCHeader"_q,
		u"noSSEHeader"_q,
		u"scMaxEachPostBytes"_q,
		u"scMinPostsIntervalMs"_q,
		u"scMaxBufferedPosts"_q,
		u"scStreamUpServerSecs"_q,
		u"serverMaxHeaderBytes"_q,
		u"xmux"_q,
	})) {
		return false;
	}
	if (object.contains(u"headers"_q)
		&& !IsHeadersObject(object.value(u"headers"_q))) {
		return false;
	}
	for (const auto &key : {
		u"xPaddingObfsMode"_q,
		u"noGRPCHeader"_q,
		u"noSSEHeader"_q,
	}) {
		if (object.contains(key) && !object.value(key).isBool()) {
			return false;
		}
	}
	if (object.contains(u"xPaddingBytes"_q)
		&& !JsonRange(
			object.value(u"xPaddingBytes"_q),
			1,
			kMaxXhttpPaddingBytes)) {
		return false;
	}
	for (const auto &key : { u"uplinkChunkSize"_q, u"scMaxEachPostBytes"_q }) {
		if (object.contains(key)
			&& !JsonRange(object.value(key), 0, kMaxXhttpUploadBytes)) {
			return false;
		}
	}
	if (object.contains(u"scMinPostsIntervalMs"_q)
		&& !JsonRange(object.value(u"scMinPostsIntervalMs"_q), 0, 60000)) {
		return false;
	}
	if (object.contains(u"scStreamUpServerSecs"_q)
		&& !JsonRange(object.value(u"scStreamUpServerSecs"_q), 0, 86400)) {
		return false;
	}
	if (object.contains(u"scMaxBufferedPosts"_q)
		&& !JsonInteger(
			object.value(u"scMaxBufferedPosts"_q),
			0,
			kMaxXhttpBufferedPosts)) {
		return false;
	}
	if (object.contains(u"serverMaxHeaderBytes"_q)
		&& !JsonInteger(
			object.value(u"serverMaxHeaderBytes"_q),
			0,
			kMaxXhttpHeaderBytes)) {
		return false;
	}
	for (const auto &key : {
		u"xPaddingKey"_q,
		u"xPaddingHeader"_q,
		u"sessionKey"_q,
		u"seqKey"_q,
		u"uplinkDataKey"_q,
	}) {
		if (object.contains(key)
			&& !IsJsonString(object.value(key), true, 256)) {
			return false;
		}
	}
	const auto hasAllowedValue = [&](const QString &key, auto values) {
		if (!object.contains(key)) {
			return true;
		} else if (!IsJsonString(object.value(key), true, 64)) {
			return false;
		}
		const auto value = object.value(key).toString();
		return value.isEmpty() || values.contains(value);
	};
	if (!hasAllowedValue(
		u"xPaddingPlacement"_q,
		QStringList{
			u"cookie"_q,
			u"header"_q,
			u"query"_q,
			u"queryInHeader"_q,
		})
		|| !hasAllowedValue(
			u"xPaddingMethod"_q,
			QStringList{ u"repeat-x"_q, u"tokenish"_q })
		|| !hasAllowedValue(
			u"sessionPlacement"_q,
			QStringList{
				u"path"_q,
				u"cookie"_q,
				u"header"_q,
				u"query"_q,
			})
		|| !hasAllowedValue(
			u"seqPlacement"_q,
			QStringList{
				u"path"_q,
				u"cookie"_q,
				u"header"_q,
				u"query"_q,
			})
		|| !hasAllowedValue(
			u"uplinkDataPlacement"_q,
			QStringList{
				u"auto"_q,
				u"body"_q,
				u"cookie"_q,
				u"header"_q,
			})) {
		return false;
	}
	if (object.contains(u"uplinkHTTPMethod"_q)) {
		const auto method = object.value(u"uplinkHTTPMethod"_q);
		if (!IsJsonString(method, true, 32)
			|| !IsHttpToken(method.toString(), true)) {
			return false;
		}
		if (method.toString().compare(u"GET"_q, Qt::CaseInsensitive) == 0
			&& mode != u"packet-up"_q) {
			return false;
		}
	}
	const auto dataPlacement = object.value(
		u"uplinkDataPlacement"_q).toString();
	if ((dataPlacement == u"cookie"_q || dataPlacement == u"header"_q)
		&& mode != u"packet-up"_q) {
		return false;
	}
	const auto keyForPlacementIsValid = [&object](
			const QString &placementKey,
			const QString &valueKey) {
		const auto placement = object.value(placementKey).toString();
		return !object.contains(valueKey)
			|| (placement != u"header"_q && placement != u"cookie"_q)
			|| IsHttpToken(object.value(valueKey).toString(), true);
	};
	if ((object.contains(u"xPaddingHeader"_q)
			&& !IsHttpToken(object.value(u"xPaddingHeader"_q).toString(), true))
		|| !keyForPlacementIsValid(u"xPaddingPlacement"_q, u"xPaddingKey"_q)
		|| !keyForPlacementIsValid(u"sessionPlacement"_q, u"sessionKey"_q)
		|| !keyForPlacementIsValid(u"seqPlacement"_q, u"seqKey"_q)
		|| !keyForPlacementIsValid(
			u"uplinkDataPlacement"_q,
			u"uplinkDataKey"_q)) {
		return false;
	}
	return !object.contains(u"xmux"_q)
		|| ValidateXmux(object.value(u"xmux"_q));
}

[[nodiscard]] bool ValidateSudoku(const QJsonObject &object) {
	if (!HasOnlyKeys(object, {
		u"password"_q,
		u"ascii"_q,
		u"customTable"_q,
		u"custom_table"_q,
		u"customTables"_q,
		u"custom_tables"_q,
		u"paddingMin"_q,
		u"padding_min"_q,
		u"paddingMax"_q,
		u"padding_max"_q,
	})) {
		return false;
	}
	if ((object.contains(u"customTable"_q)
			&& object.contains(u"custom_table"_q))
		|| (object.contains(u"customTables"_q)
			&& object.contains(u"custom_tables"_q))
		|| (object.contains(u"paddingMin"_q)
			&& object.contains(u"padding_min"_q))
		|| (object.contains(u"paddingMax"_q)
			&& object.contains(u"padding_max"_q))) {
		return false;
	}
	if (object.contains(u"password"_q)
		&& !IsJsonString(object.value(u"password"_q), true, 2048)) {
		return false;
	}
	if (object.contains(u"ascii"_q)) {
		if (!IsJsonString(object.value(u"ascii"_q), true, 32)) {
			return false;
		}
		const auto value = object.value(u"ascii"_q).toString().trimmed().toLower();
		if (!IsOneOf(value, {
			u""_q,
			u"entropy"_q,
			u"prefer_entropy"_q,
			u"ascii"_q,
			u"prefer_ascii"_q,
		})) {
			return false;
		}
	}
	for (const auto &key : { u"customTable"_q, u"custom_table"_q }) {
		if (object.contains(key)
			&& (!object.value(key).isString()
				|| !IsSudokuPattern(object.value(key).toString()))) {
			return false;
		}
	}
	for (const auto &key : {
		u"customTables"_q,
		u"custom_tables"_q,
	}) {
		if (object.contains(key) && !IsSudokuPatternArray(object.value(key))) {
			return false;
		}
	}
	for (const auto &key : {
		u"paddingMin"_q,
		u"padding_min"_q,
		u"paddingMax"_q,
		u"padding_max"_q,
	}) {
		if (object.contains(key)
			&& !JsonInteger(object.value(key), 0, 100)) {
			return false;
		}
	}
	const auto paddingValue = [&object](
			const QString &canonical,
			const QString &legacy) {
		const auto key = object.contains(canonical) ? canonical : legacy;
		return object.contains(key) ? object.value(key).toInt() : 0;
	};
	const auto hasPaddingMin = object.contains(u"paddingMin"_q)
		|| object.contains(u"padding_min"_q);
	const auto hasPaddingMax = object.contains(u"paddingMax"_q)
		|| object.contains(u"padding_max"_q);
	if (hasPaddingMin
		&& hasPaddingMax
		&& paddingValue(u"paddingMin"_q, u"padding_min"_q)
		> paddingValue(u"paddingMax"_q, u"padding_max"_q)) {
		return false;
	}
	return true;
}

[[nodiscard]] bool ValidateFragment(const QJsonObject &object) {
	if (!HasOnlyKeys(object, {
		u"packets"_q,
		u"length"_q,
		u"delay"_q,
		u"maxSplit"_q,
	})
		|| !object.contains(u"length"_q)
		|| !JsonRange(object.value(u"length"_q), 1, 65535)) {
		return false;
	}
	if (object.contains(u"packets"_q)
		&& !IsJsonString(object.value(u"packets"_q), true, 64)) {
		return false;
	}
	for (const auto &key : { u"delay"_q, u"maxSplit"_q }) {
		if (object.contains(key)
			&& !JsonRange(object.value(key), 0, 60000)) {
			return false;
		}
	}
	return true;
}

[[nodiscard]] bool ValidateFinalMaskSettings(
		const QString &type,
		const QJsonObject &settings,
		bool tcp) {
	if (tcp) {
		if (type == u"fragment"_q) {
			return ValidateFragment(settings);
		} else if (type == u"sudoku"_q) {
			return ValidateSudoku(settings);
		}
		return false;
	}
	if (IsOneOf(type, {
		u"header-dtls"_q,
		u"header-srtp"_q,
		u"header-utp"_q,
		u"header-wechat"_q,
		u"header-wireguard"_q,
		u"mkcp-original"_q,
	})) {
		return settings.isEmpty();
	} else if (type == u"header-dns"_q) {
		return HasOnlyKeys(settings, { u"domain"_q })
			&& (!settings.contains(u"domain"_q)
				|| IsJsonString(settings.value(u"domain"_q), true, 255));
	} else if (type == u"xdns"_q) {
		return HasOnlyKeys(settings, { u"domain"_q })
			&& settings.contains(u"domain"_q)
			&& IsJsonString(settings.value(u"domain"_q), false, 255);
	} else if (IsOneOf(
		type,
		{ u"mkcp-aes128gcm"_q, u"salamander"_q })) {
		return HasOnlyKeys(settings, { u"password"_q })
			&& (!settings.contains(u"password"_q)
				|| IsJsonString(
					settings.value(u"password"_q),
					true,
					1024));
	} else if (type == u"sudoku"_q) {
		return ValidateSudoku(settings);
	}
	return false;
}

[[nodiscard]] bool ValidateFinalMaskArray(
		const QJsonValue &value,
		bool tcp) {
	if (!value.isArray() || value.toArray().size() > 8) {
		return false;
	}
	for (const auto &entry : value.toArray()) {
		if (!entry.isObject()) {
			return false;
		}
		const auto mask = entry.toObject();
		if (!HasOnlyKeys(mask, { u"type"_q, u"settings"_q })
			|| !IsJsonString(mask.value(u"type"_q), false, 64)) {
			return false;
		}
		const auto settings = mask.contains(u"settings"_q)
			? mask.value(u"settings"_q)
			: QJsonValue(QJsonObject());
		if (!settings.isObject()
			|| !ValidateFinalMaskSettings(
				mask.value(u"type"_q).toString(),
				settings.toObject(),
				tcp)) {
			return false;
		}
	}
	return true;
}

[[nodiscard]] bool ValidateFinalMask(const QJsonObject &object) {
	return HasOnlyKeys(object, { u"tcp"_q, u"udp"_q })
		&& (!object.contains(u"tcp"_q)
			|| ValidateFinalMaskArray(object.value(u"tcp"_q), true))
		&& (!object.contains(u"udp"_q)
			|| ValidateFinalMaskArray(object.value(u"udp"_q), false));
}

[[nodiscard]] bool IsKnownParameter(const QString &key) {
	static const auto keys = QStringList{
		u"type"_q,
		u"encryption"_q,
		u"flow"_q,
		u"security"_q,
		u"path"_q,
		u"host"_q,
		u"mtu"_q,
		u"tti"_q,
		u"serviceName"_q,
		u"mode"_q,
		u"authority"_q,
		u"extra"_q,
		u"fm"_q,
		u"fp"_q,
		u"sni"_q,
		u"alpn"_q,
		u"ech"_q,
		u"pcs"_q,
		u"vcn"_q,
		u"pbk"_q,
		u"sid"_q,
		u"pqv"_q,
		u"spx"_q,
		u"headerType"_q,
	};
	return keys.contains(key);
}

[[nodiscard]] bool IsParameterApplicable(
		const QString &key,
		const QString &transport,
		const QString &security) {
	if (IsOneOf(key, {
		u"type"_q,
		u"encryption"_q,
		u"flow"_q,
		u"security"_q,
		u"fm"_q,
	})) {
		return true;
	} else if (key == u"path"_q || key == u"host"_q) {
		return transport == u"websocket"_q
			|| transport == u"httpupgrade"_q
			|| transport == u"xhttp"_q;
	} else if (key == u"mtu"_q || key == u"tti"_q) {
		return transport == u"mkcp"_q;
	} else if (key == u"serviceName"_q || key == u"authority"_q) {
		return transport == u"grpc"_q;
	} else if (key == u"mode"_q) {
		return transport == u"grpc"_q || transport == u"xhttp"_q;
	} else if (key == u"extra"_q) {
		return transport == u"xhttp"_q;
	} else if (key == u"headerType"_q) {
		return transport == u"raw"_q || transport == u"mkcp"_q;
	} else if (key == u"fp"_q || key == u"sni"_q) {
		return security == u"tls"_q || security == u"reality"_q;
	} else if (key == u"alpn"_q) {
		return security == u"tls"_q
			|| (security == u"reality"_q && transport == u"grpc"_q);
	} else if (IsOneOf(key, { u"ech"_q, u"pcs"_q, u"vcn"_q })) {
		return security == u"tls"_q;
	} else if (IsOneOf(
		key,
		{ u"pbk"_q, u"sid"_q, u"pqv"_q, u"spx"_q })) {
		return security == u"reality"_q;
	}
	return false;
}

[[nodiscard]] std::optional<QString> NormalizeTransport(
		const QMap<QString, QString> &parameters) {
	if (!parameters.contains(u"type"_q)) {
		return u"raw"_q;
	}
	const auto value = parameters.value(u"type"_q);
	if (IsOneOf(value, { u"tcp"_q, u"raw"_q })) {
		return u"raw"_q;
	} else if (IsOneOf(value, { u"kcp"_q, u"mkcp"_q })) {
		return u"mkcp"_q;
	} else if (IsOneOf(value, { u"ws"_q, u"websocket"_q })) {
		return u"websocket"_q;
	} else if (IsOneOf(value, { u"grpc"_q, u"httpupgrade"_q })) {
		return value;
	} else if (IsOneOf(value, { u"xhttp"_q, u"splithttp"_q })) {
		return u"xhttp"_q;
	}
	return std::nullopt;
}

[[nodiscard]] bool IsLocalCredentialValid(const QString &value) {
	if (value.isEmpty() || ContainsRawControl(value)) {
		return false;
	}
	const auto encoded = value.toUtf8();
	return encoded.size() <= kMaxSocksCredentialBytes
		&& QString::fromUtf8(encoded) == value;
}

} // namespace

VlessProfileResult ParseVlessProfile(QStringView uri) {
	if (uri.isEmpty()) {
		return Fail(VlessProfileError::Empty);
	} else if (uri.size() > kMaxProfileBytes) {
		return Fail(VlessProfileError::TooLong);
	}

	const auto text = uri.toString();
	const auto encoded = text.toUtf8();
	if (encoded.size() > kMaxProfileBytes) {
		return Fail(VlessProfileError::TooLong);
	} else if (QString::fromUtf8(encoded) != text
		|| ContainsRawControl(text)) {
		return Fail(VlessProfileError::InvalidUri);
	}

	const auto schemeEnd = text.indexOf(u"://"_q);
	if (schemeEnd < 0 || text.left(schemeEnd) != u"vless"_q) {
		return Fail(VlessProfileError::InvalidUri);
	}
	const auto url = QUrl(text, QUrl::StrictMode);
	if (!url.isValid() || url.scheme() != u"vless"_q) {
		return Fail(VlessProfileError::InvalidUri);
	}
	if (ContainsRawControl(url.fragment(QUrl::FullyDecoded))) {
		return Fail(VlessProfileError::InvalidUri);
	}

	const auto authorityStart = schemeEnd + 3;
	auto authorityEnd = text.size();
	for (const auto delimiter : { QChar('/'), QChar('?'), QChar('#') }) {
		const auto position = text.indexOf(delimiter, authorityStart);
		if (position >= 0 && position < authorityEnd) {
			authorityEnd = position;
		}
	}
	const auto authority = text.mid(authorityStart, authorityEnd - authorityStart);
	if (authority.count(QChar('@')) != 1) {
		return Fail(VlessProfileError::InvalidUser);
	}
	const auto separator = authority.indexOf(QChar('@'));
	const auto rawUser = authority.left(separator);
	if (rawUser.isEmpty() || rawUser.contains(QChar(':'))) {
		return Fail(VlessProfileError::InvalidUser);
	}
	const auto decodedUser = PercentDecode(rawUser.toUtf8());
	if (!decodedUser) {
		return Fail(VlessProfileError::InvalidUser);
	}
	const auto userId = decodedUser->toLower();
	if (!IsCanonicalUuid(userId)) {
		return Fail(VlessProfileError::InvalidUserId);
	}
	if (!url.password(QUrl::FullyDecoded).isEmpty()
		|| url.userName(QUrl::FullyDecoded).toLower() != userId) {
		return Fail(VlessProfileError::InvalidUser);
	}

	if (!url.path().isEmpty()) {
		return Fail(VlessProfileError::InvalidUri);
	}
	const auto host = url.host(QUrl::FullyDecoded);
	if (host.isEmpty()
		|| ContainsSpace(host)
		|| !IsSafeString(host, 255)) {
		return Fail(VlessProfileError::InvalidHost);
	}
	const auto port = url.port(-1);
	if (port < 1 || port > 65535) {
		return Fail(VlessProfileError::InvalidPort);
	}

	auto parameters = QMap<QString, QString>();
	const auto question = encoded.indexOf('?');
	const auto hash = encoded.indexOf('#');
	const auto hasQuery = question >= 0 && (hash < 0 || question < hash);
	if (hasQuery) {
		const auto queryEnd = (hash < 0) ? encoded.size() : hash;
		const auto query = encoded.mid(question + 1, queryEnd - question - 1);
		if (!query.isEmpty()) {
			const auto fields = query.split('&');
			if (fields.size() > kMaxQueryFields) {
				return Fail(VlessProfileError::InvalidQuery);
			}
			for (const auto &field : fields) {
				const auto equals = field.indexOf('=');
				if (field.isEmpty() || equals < 0) {
					return Fail(VlessProfileError::InvalidQuery);
				}
				const auto key = PercentDecode(field.left(equals));
				const auto value = PercentDecode(field.mid(equals + 1));
				if (!key
					|| !value
					|| key->isEmpty()
					|| ContainsRawControl(*key)
					|| ContainsRawControl(*value)) {
					return Fail(VlessProfileError::InvalidQuery);
				} else if (parameters.contains(*key)) {
					return Fail(VlessProfileError::DuplicateParameter);
				}
				parameters.insert(*key, *value);
			}
		}
	}

	for (auto i = parameters.cbegin(); i != parameters.cend(); ++i) {
		if (!IsKnownParameter(i.key())) {
			return Fail(VlessProfileError::UnsupportedParameter);
		}
	}

	const auto normalizedTransport = NormalizeTransport(parameters);
	if (!normalizedTransport) {
		return Fail(VlessProfileError::UnsupportedTransport);
	}
	const auto transport = *normalizedTransport;
	const auto encryption = parameters.contains(u"encryption"_q)
		? parameters.value(u"encryption"_q)
		: u"none"_q;
	if (encryption.isEmpty()
		|| (encryption != u"none"_q
			&& !IsMlkemEncryptionValid(encryption))) {
		return Fail(VlessProfileError::UnsupportedEncryption);
	}
	const auto flow = parameters.value(u"flow"_q);
	if (!flow.isEmpty()
		&& flow != u"xtls-rprx-vision"_q
		&& flow != u"xtls-rprx-vision-udp443"_q) {
		return Fail(VlessProfileError::UnsupportedFlow);
	}
	const auto security = parameters.contains(u"security"_q)
		? parameters.value(u"security"_q)
		: u"none"_q;
	if (security != u"none"_q
		&& security != u"tls"_q
		&& security != u"reality"_q) {
		return Fail(VlessProfileError::UnsupportedSecurity);
	} else if (security == u"reality"_q
		&& transport != u"raw"_q
		&& transport != u"xhttp"_q
		&& transport != u"grpc"_q) {
		return Fail(VlessProfileError::UnsupportedSecurity);
	} else if (security == u"none"_q && encryption == u"none"_q) {
		return Fail(VlessProfileError::UnsupportedSecurity);
	}
	if (!flow.isEmpty()
		&& encryption == u"none"_q
		&& (transport != u"raw"_q
			|| (security != u"tls"_q && security != u"reality"_q))) {
		return Fail(VlessProfileError::UnsupportedFlow);
	}

	for (auto i = parameters.cbegin(); i != parameters.cend(); ++i) {
		if (!IsParameterApplicable(i.key(), transport, security)) {
			return Fail(VlessProfileError::UnsupportedParameter);
		}
	}
	if (parameters.contains(u"headerType"_q)
		&& parameters.value(u"headerType"_q) != u"none"_q) {
		return Fail(VlessProfileError::UnsupportedHeader);
	}

	auto path = QString();
	auto transportHost = QString();
	auto kcpMtu = 0;
	auto kcpTti = 0;
	auto grpcServiceName = QString();
	auto grpcMode = QString();
	auto grpcAuthority = QString();
	auto xhttpMode = QString();
	auto xhttpExtra = QJsonObject();
	auto hasXhttpExtra = false;
	if (transport == u"websocket"_q
		|| transport == u"httpupgrade"_q
		|| transport == u"xhttp"_q) {
		path = parameters.contains(u"path"_q)
			? parameters.value(u"path"_q)
			: u"/"_q;
		transportHost = parameters.value(u"host"_q);
		if (path.isEmpty()
			|| !path.startsWith('/')
			|| !IsSafeString(path)
			|| !IsSafeString(transportHost, 1024)) {
			return Fail(VlessProfileError::InvalidTransportSettings);
		}
	} else if (transport == u"mkcp"_q) {
		if (parameters.contains(u"mtu"_q)) {
			const auto parsed = ParseBoundedInteger(
				parameters.value(u"mtu"_q),
				576,
				1460);
			if (!parsed) {
				return Fail(VlessProfileError::InvalidTransportSettings);
			}
			kcpMtu = *parsed;
		}
		if (parameters.contains(u"tti"_q)) {
			const auto parsed = ParseBoundedInteger(
				parameters.value(u"tti"_q),
				10,
				100);
			if (!parsed) {
				return Fail(VlessProfileError::InvalidTransportSettings);
			}
			kcpTti = *parsed;
		}
	} else if (transport == u"grpc"_q) {
		grpcServiceName = parameters.value(u"serviceName"_q);
		grpcAuthority = parameters.value(u"authority"_q);
		grpcMode = parameters.contains(u"mode"_q)
			? parameters.value(u"mode"_q)
			: u"gun"_q;
		if ((parameters.contains(u"serviceName"_q)
				&& grpcServiceName.isEmpty())
			|| !IsSafeString(grpcServiceName, 1024)
			|| !IsSafeString(grpcAuthority, 1024)
			|| ContainsSpace(grpcAuthority)
			|| (grpcMode != u"gun"_q && grpcMode != u"multi"_q)) {
			return Fail(VlessProfileError::InvalidTransportSettings);
		}
	}
	if (transport == u"xhttp"_q) {
		xhttpMode = parameters.value(u"mode"_q);
		if (xhttpMode.isEmpty()) {
			xhttpMode = u"auto"_q;
		} else if (xhttpMode != u"auto"_q
			&& xhttpMode != u"packet-up"_q
			&& xhttpMode != u"stream-up"_q
			&& xhttpMode != u"stream-one"_q) {
			return Fail(VlessProfileError::InvalidTransportSettings);
		}
		if (parameters.contains(u"extra"_q)) {
			const auto parsed = ParseJsonObject(parameters.value(u"extra"_q));
			if (!parsed || !ValidateXhttpExtra(*parsed, xhttpMode)) {
				return Fail(VlessProfileError::InvalidJson);
			}
			xhttpExtra = *parsed;
			hasXhttpExtra = true;
		}
	}

	auto finalMask = QJsonObject();
	auto hasFinalMask = false;
	if (parameters.contains(u"fm"_q)) {
		const auto parsed = ParseJsonObject(parameters.value(u"fm"_q));
		if (!parsed || !ValidateFinalMask(*parsed)) {
			return Fail(VlessProfileError::InvalidJson);
		}
		finalMask = *parsed;
		hasFinalMask = true;
	}

	auto serverName = QString();
	auto fingerprint = QString();
	auto alpn = QStringList();
	auto ech = QString();
	auto hasEch = false;
	auto pinnedPeerCertSha256 = QString();
	auto hasPinnedPeerCertSha256 = false;
	auto verifyPeerCertByName = QString();
	auto hasVerifyPeerCertByName = false;
	auto publicKey = QString();
	auto shortId = QString();
	auto hasShortId = false;
	auto mldsa65Verify = QString();
	auto hasMldsa65Verify = false;
	auto spiderX = QString();
	auto hasSpiderX = false;
	if (security == u"tls"_q || security == u"reality"_q) {
		serverName = parameters.contains(u"sni"_q)
			? parameters.value(u"sni"_q)
			: host;
		if (!IsServerNameValid(serverName)) {
			return Fail(VlessProfileError::InvalidServerName);
		}
		fingerprint = parameters.contains(u"fp"_q)
			? parameters.value(u"fp"_q)
			: u"chrome"_q;
		if ((security == u"reality"_q && !parameters.contains(u"fp"_q))
			|| !IsFingerprintSupported(fingerprint)) {
			return Fail(VlessProfileError::UnsupportedFingerprint);
		}
	}
	if (parameters.contains(u"alpn"_q)) {
		const auto parsed = ParseAlpn(parameters.value(u"alpn"_q));
		if (!parsed) {
			return Fail(VlessProfileError::InvalidAlpn);
		}
		alpn = *parsed;
		if ((transport == u"grpc"_q && alpn[0] != u"h2"_q)
			|| ((transport == u"websocket"_q
					|| transport == u"httpupgrade"_q)
				&& alpn[0] != u"http/1.1"_q)) {
			return Fail(VlessProfileError::InvalidAlpn);
		}
	}
	if (security == u"tls"_q) {
		hasEch = parameters.contains(u"ech"_q);
		ech = parameters.value(u"ech"_q);
		if (hasEch && !IsEchValid(ech)) {
			return Fail(VlessProfileError::InvalidSecuritySettings);
		}
		hasPinnedPeerCertSha256 = parameters.contains(u"pcs"_q);
		pinnedPeerCertSha256 = parameters.value(u"pcs"_q);
		if (hasPinnedPeerCertSha256
			&& !IsCertificatePinListValid(pinnedPeerCertSha256)) {
			return Fail(VlessProfileError::InvalidCertificatePin);
		}
		hasVerifyPeerCertByName = parameters.contains(u"vcn"_q);
		verifyPeerCertByName = parameters.value(u"vcn"_q);
		if (hasVerifyPeerCertByName
			&& !IsVerifyNameListValid(verifyPeerCertByName)) {
			return Fail(VlessProfileError::InvalidVerifyName);
		}
	} else if (security == u"reality"_q) {
		if (!parameters.contains(u"pbk"_q)) {
			return Fail(VlessProfileError::InvalidPublicKey);
		}
		publicKey = parameters.value(u"pbk"_q);
		if (!IsPublicKeyValid(publicKey)) {
			return Fail(VlessProfileError::InvalidPublicKey);
		}
		hasShortId = parameters.contains(u"sid"_q);
		shortId = parameters.value(u"sid"_q);
		if (hasShortId && !IsShortIdValid(shortId)) {
			return Fail(VlessProfileError::InvalidShortId);
		}
		hasMldsa65Verify = parameters.contains(u"pqv"_q);
		mldsa65Verify = parameters.value(u"pqv"_q);
		if (hasMldsa65Verify
			&& !mldsa65Verify.isEmpty()
			&& !IsMldsa65VerifyValid(mldsa65Verify)) {
			return Fail(VlessProfileError::InvalidMldsaVerify);
		}
		hasSpiderX = parameters.contains(u"spx"_q);
		spiderX = parameters.value(u"spx"_q);
		if (hasSpiderX
			&& !spiderX.isEmpty()
			&& (!spiderX.startsWith('/') || !IsSafeString(spiderX))) {
			return Fail(VlessProfileError::InvalidSpiderPath);
		}
	}

	auto profile = VlessProfile();
	profile.endpointHost = host;
	profile.endpointPort = uint16(port);
	profile._userId = userId;
	profile._encryption = encryption;
	profile._flow = flow;
	profile._transport = transport;
	profile._security = security;
	profile._path = path;
	profile._transportHost = transportHost;
	profile._kcpMtu = kcpMtu;
	profile._kcpTti = kcpTti;
	profile._grpcServiceName = grpcServiceName;
	profile._grpcMode = grpcMode;
	profile._grpcAuthority = grpcAuthority;
	profile._xhttpMode = xhttpMode;
	profile._xhttpExtra = xhttpExtra;
	profile._hasXhttpExtra = hasXhttpExtra;
	profile._finalMask = finalMask;
	profile._hasFinalMask = hasFinalMask;
	profile._serverName = serverName;
	profile._fingerprint = fingerprint;
	profile._alpn = alpn;
	profile._ech = ech;
	profile._hasEch = hasEch;
	profile._pinnedPeerCertSha256 = pinnedPeerCertSha256;
	profile._hasPinnedPeerCertSha256 = hasPinnedPeerCertSha256;
	profile._verifyPeerCertByName = verifyPeerCertByName;
	profile._hasVerifyPeerCertByName = hasVerifyPeerCertByName;
	profile._publicKey = publicKey;
	profile._shortId = shortId;
	profile._hasShortId = hasShortId;
	profile._mldsa65Verify = mldsa65Verify;
	profile._hasMldsa65Verify = hasMldsa65Verify;
	profile._spiderX = spiderX;
	profile._hasSpiderX = hasSpiderX;
	return {
		.profile = std::move(profile),
		.error = VlessProfileError::None,
	};
}

QByteArray VlessProfile::xrayConfig(
		const VlessLocalInbound &socks,
		const VlessLocalInbound &http) const {
	if (!socks.port
		|| !http.port
		|| socks.port == http.port
		|| !endpointPort
		|| endpointHost.isEmpty()
		|| ContainsSpace(endpointHost)
		|| !IsSafeString(endpointHost, 255)
		|| _userId.isEmpty()
		|| _encryption.isEmpty()
		|| _transport.isEmpty()
		|| _security.isEmpty()
		|| !IsLocalCredentialValid(socks.user)
		|| !IsLocalCredentialValid(socks.password)
		|| !IsLocalCredentialValid(http.user)
		|| !IsLocalCredentialValid(http.password)) {
		return {};
	}

	auto user = QJsonObject{
		{ u"id"_q, _userId },
		{ u"encryption"_q, _encryption },
	};
	if (!_flow.isEmpty()) {
		user.insert(u"flow"_q, _flow);
	}

	auto stream = QJsonObject{
		{ u"network"_q, _transport },
		{ u"security"_q, _security },
	};
	if (_transport == u"mkcp"_q) {
		auto settings = QJsonObject();
		if (_kcpMtu) {
			settings.insert(u"mtu"_q, _kcpMtu);
		}
		if (_kcpTti) {
			settings.insert(u"tti"_q, _kcpTti);
		}
		stream.insert(u"kcpSettings"_q, settings);
	} else if (_transport == u"websocket"_q) {
		stream.insert(u"wsSettings"_q, QJsonObject{
			{ u"path"_q, _path },
			{ u"host"_q, _transportHost },
		});
	} else if (_transport == u"grpc"_q) {
		stream.insert(u"grpcSettings"_q, QJsonObject{
			{ u"serviceName"_q, _grpcServiceName },
			{ u"authority"_q, _grpcAuthority },
			{ u"multiMode"_q, _grpcMode == u"multi"_q },
		});
	} else if (_transport == u"httpupgrade"_q) {
		stream.insert(u"httpupgradeSettings"_q, QJsonObject{
			{ u"path"_q, _path },
			{ u"host"_q, _transportHost },
		});
	} else if (_transport == u"xhttp"_q) {
		auto settings = QJsonObject{
			{ u"path"_q, _path },
			{ u"host"_q, _transportHost },
			{ u"mode"_q, _xhttpMode },
		};
		if (_hasXhttpExtra) {
			settings.insert(u"extra"_q, _xhttpExtra);
		}
		stream.insert(u"xhttpSettings"_q, settings);
	}

	if (_security == u"tls"_q) {
		auto settings = QJsonObject{
			{ u"serverName"_q, _serverName },
			{ u"fingerprint"_q, _fingerprint },
		};
		if (!_alpn.isEmpty()) {
			settings.insert(u"alpn"_q, QJsonArray::fromStringList(_alpn));
		}
		if (_hasEch) {
			settings.insert(u"echConfigList"_q, _ech);
		}
		if (_hasPinnedPeerCertSha256) {
			settings.insert(
				u"pinnedPeerCertSha256"_q,
				_pinnedPeerCertSha256);
		}
		if (_hasVerifyPeerCertByName) {
			settings.insert(
				u"verifyPeerCertByName"_q,
				_verifyPeerCertByName);
		}
		stream.insert(u"tlsSettings"_q, settings);
	} else if (_security == u"reality"_q) {
		auto settings = QJsonObject{
			{ u"serverName"_q, _serverName },
			{ u"fingerprint"_q, _fingerprint },
			{ u"password"_q, _publicKey },
		};
		if (_hasShortId) {
			settings.insert(u"shortId"_q, _shortId);
		}
		if (_hasMldsa65Verify) {
			settings.insert(u"mldsa65Verify"_q, _mldsa65Verify);
		}
		if (_hasSpiderX) {
			settings.insert(u"spiderX"_q, _spiderX);
		}
		stream.insert(u"realitySettings"_q, settings);
	}
	if (_hasFinalMask) {
		stream.insert(u"finalmask"_q, _finalMask);
	}

	const auto root = QJsonObject{
		{
			u"log"_q,
			QJsonObject{
				{ u"access"_q, u"none"_q },
				{ u"loglevel"_q, u"warning"_q },
			}
		},
		{
			u"inbounds"_q,
			QJsonArray{
				QJsonObject{
					{ u"tag"_q, u"telegram-socks"_q },
					{ u"listen"_q, u"127.0.0.1"_q },
					{ u"port"_q, int(socks.port) },
					{ u"protocol"_q, u"socks"_q },
					{
						u"settings"_q,
						QJsonObject{
							{ u"auth"_q, u"password"_q },
							{
								u"accounts"_q,
								QJsonArray{
									QJsonObject{
										{ u"user"_q, socks.user },
										{ u"pass"_q, socks.password },
									}
								}
							},
							{ u"udp"_q, true },
						}
					},
				},
				QJsonObject{
					{ u"tag"_q, u"telegram-web"_q },
					{ u"listen"_q, u"127.0.0.1"_q },
					{ u"port"_q, int(http.port) },
					{ u"protocol"_q, u"http"_q },
					{
						u"settings"_q,
						QJsonObject{
							{
								u"accounts"_q,
								QJsonArray{
									QJsonObject{
										{ u"user"_q, http.user },
										{ u"pass"_q, http.password },
									}
								}
							},
							{ u"allowTransparent"_q, false },
						}
					},
				}
			}
		},
		{
			u"outbounds"_q,
			QJsonArray{
				QJsonObject{
					{ u"tag"_q, u"vless-out"_q },
					{ u"protocol"_q, u"vless"_q },
					{
						u"settings"_q,
						QJsonObject{
							{
								u"vnext"_q,
								QJsonArray{
									QJsonObject{
										{ u"address"_q, endpointHost },
										{ u"port"_q, int(endpointPort) },
										{
											u"users"_q,
											QJsonArray{ user },
										},
									}
								}
							}
						}
					},
					{ u"streamSettings"_q, stream },
				}
			}
		},
	};
	return QJsonDocument(root).toJson(QJsonDocument::Compact);
}

} // namespace Core
