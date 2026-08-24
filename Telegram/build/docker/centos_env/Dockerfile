# syntax=docker/dockerfile:1

FROM --platform=linux/amd64 docker.io/library/rockylinux@sha256:2d05a9266523bbf24f33ebc3a9832e4d5fd74b973c220f2204ca802286aa275d AS builder
SHELL ["/bin/bash", "-euo", "pipefail", "-c"]

ENV LANG=C.UTF-8
ENV TOOLSET=gcc-toolset-15
ENV PATH=/opt/rh/$TOOLSET/root/usr/bin:$PATH
ENV LIBRARY_PATH=/opt/rh/$TOOLSET/root/usr/lib64:/opt/rh/$TOOLSET/root/usr/lib:/usr/local/lib64:/usr/local/lib:/lib64:/lib:/usr/lib64:/usr/lib
ENV LD_LIBRARY_PATH=$LIBRARY_PATH
ENV PKG_CONFIG_PATH=/opt/rh/$TOOLSET/root/usr/lib64/pkgconfig:/opt/rh/$TOOLSET/root/usr/lib/pkgconfig:/usr/local/lib64/pkgconfig:/usr/local/lib/pkgconfig:/usr/local/share/pkgconfig

RUN --mount=type=cache,target=/var/cache/dnf <<EOF
dnf -y install epel-release
dnf config-manager --set-enabled powertools
dnf -y install cmake autoconf automake libtool pkgconfig make patch git \
	python3.11-pip python3.11-devel gperf flex bison clang-tools-extra \
	lld ccache nasm file which wget perl-open perl-XML-Parser perl-IPC-Cmd \
	xorg-x11-util-macros $TOOLSET-gcc $TOOLSET-gcc-c++ $TOOLSET-binutils \
	$TOOLSET-gdb $TOOLSET-libasan-devel libffi-devel fontconfig-devel \
	freetype-devel libX11-devel wayland-devel alsa-lib-devel \
	pulseaudio-libs-devel mesa-libGL-devel mesa-libEGL-devel mesa-libgbm-devel \
	libdrm-devel vulkan-devel libva-devel libvdpau-devel libselinux-devel \
	libmount-devel systemd-devel glib2-devel gobject-introspection-devel \
	at-spi2-core-devel gtk3-devel
EOF

RUN <<EOF
alternatives --set python3 /usr/bin/python3.11
EOF

RUN <<EOF
cat <<CAT > /usr/local/bin/pkg-config
#!/bin/sh
for i in "\$@"; do
	[ "\$i" = "--version" ] && exec /usr/bin/pkg-config "\$i"
done
exec /usr/bin/pkg-config --static "\$@"
CAT
chmod +x /usr/local/bin/pkg-config

CMAKE_ROOT="$(cmake --system-information | sed -n 's/^CMAKE_ROOT "\([^"]*\)"$/\1/p')"
test -n "$CMAKE_ROOT"
sed -i '/CMAKE_${lang}_FLAGS_DEBUG_INIT/s/")/ -O0 {% if LTO %}-fno-lto -fno-use-linker-plugin{% endif %}")/' "$CMAKE_ROOT/Modules/Compiler/GNU.cmake"
for i in EXE SHARED MODULE; do
	sed -i '1i string(APPEND CMAKE_'$i'_LINKER_FLAGS_DEBUG_INIT " -fuse-ld=lld")' "$CMAKE_ROOT/Modules/CMakeCommonLanguageInclude.cmake"
done
sed -i '/CMAKE_EXE_LINKER_FLAGS_INIT/s/")/ -Wl,--exclude-libs,ALL")/' "$CMAKE_ROOT/Modules/CMakeCommonLanguageInclude.cmake"
sed -i '/__gcc_hints/d' "$CMAKE_ROOT/Modules/Compiler/GNU-FindBinUtils.cmake"
sed -i '1i set(_CMAKE_TOOLCHAIN_LOCATION "")' "$CMAKE_ROOT/Modules/CMakeFindBinUtils.cmake"
sed -i 's/NO_DEFAULT_PATH//g; s/PKG_CONFIG_ALLOW_SYSTEM_LIBS/PKG_CONFIG_IS_DUMB/g' "$CMAKE_ROOT/Modules/FindPkgConfig.cmake"
sed -i '/Requires.private: valgrind/d' /usr/lib64/pkgconfig/libdrm.pc
sed -i '/Requires.private: gl/s/gl/opengl glx/' /usr/lib64/pkgconfig/epoxy.pc
sed -i 's/-lharfbuzz//' /usr/lib64/pkgconfig/harfbuzz.pc
sed -i 's/-lpng16//' /usr/lib64/pkgconfig/libpng16.pc

rm /etc/profile.d/ccache.*
echo set debuginfod enabled on > /opt/rh/$TOOLSET/root/etc/gdbinit.d/00-debuginfod.gdb
adduser user
EOF

RUN <<'EOF'
cat > /usr/local/bin/tevless-verify-source <<'PY'
#!/usr/bin/python3
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path


def fail(message):
    raise SystemExit("TeVLESS source verification failed: " + message)


def git_output(*arguments):
    try:
        return subprocess.run(
            ["git", *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ).stdout.rstrip("\n")
    except (OSError, subprocess.CalledProcessError) as error:
        fail("git command failed: " + " ".join(arguments))


if len(sys.argv) < 12:
    fail("invalid verifier arguments")
kind, name, origin, revision, resolved, submodule_policy, expected_submodules_sha256, archive, archive_sha256, output_root = sys.argv[1:11]
extra = sys.argv[11:]
if kind not in {"git", "upstream-archive"}:
    fail("invalid source kind")
if not re.fullmatch(r"[a-z0-9][a-z0-9._+-]*", name):
    fail("invalid dependency name")
if not origin.startswith("https://"):
    fail("source origin is not HTTPS")
if not re.fullmatch(r"[0-9a-f]{64}", archive_sha256):
    fail("invalid source archive SHA-256")
if not os.path.isabs(output_root):
    fail("provenance output root is not absolute")

submodules = []
actual_fetch_sha256 = None
if kind == "git":
    if len(extra) < 1:
        fail("Git source is missing its repository path")
    repository, *selected = extra
    if not re.fullmatch(r"[0-9a-f]{40}", resolved):
        fail("resolved Git revision is not a full commit")
    if submodule_policy not in {"none", "recursive", "selected"}:
        fail("invalid submodule policy")
    if not re.fullmatch(r"[0-9a-f]{64}", expected_submodules_sha256):
        fail("invalid recursive submodule inventory SHA-256")
    if (submodule_policy == "selected") != bool(selected):
        fail("selected submodule paths differ from policy")
    if submodule_policy != "selected" and selected:
        fail("unexpected selected submodule paths")
    os.chdir(repository)
    if git_output("remote", "get-url", "origin").rstrip("/") != origin.rstrip("/"):
        fail(name + " origin differs")
    actual_head = git_output("rev-parse", "--verify", "HEAD^{commit}")
    if actual_head != resolved:
        fail(name + " HEAD differs from resolved revision")
    if git_output("status", "--porcelain=v1", "--untracked-files=all"):
        fail(name + " checkout is not clean at source verification")
    arguments = ["submodule", "status", "--recursive"]
    if selected:
        arguments.extend(["--", *selected])
    raw_status = git_output(*arguments)
    if "\r" in raw_status or "\0" in raw_status:
        fail(name + " submodule status contains unsafe bytes")
    seen = set()
    for line in raw_status.splitlines():
        if not line:
            continue
        match = re.fullmatch(r"([ +\-U])([0-9a-f]{40}) ([^ ]+)(?: .*)?", line)
        if match is None:
            fail(name + " submodule status is malformed")
        state, commit, path = match.groups()
        if submodule_policy == "none":
            if state != "-":
                fail(name + " unexpectedly initialized a submodule")
            continue
        if state != " ":
            fail(name + " submodule is not at its exact initialized gitlink")
        if path in seen:
            fail(name + " has duplicate submodule paths")
        seen.add(path)
        submodules.append({"path": path, "revision": commit})
    submodules.sort(key=lambda item: item["path"])
    canonical_submodules = "".join(
        item["path"] + "\t" + item["revision"] + "\n" for item in submodules
    ).encode("utf-8")
    actual_submodules_sha256 = hashlib.sha256(canonical_submodules).hexdigest()
    if actual_submodules_sha256 != expected_submodules_sha256:
        fail(name + " recursive submodule inventory differs")
elif kind == "upstream-archive":
    if submodule_policy != "none" or expected_submodules_sha256 != "-" or len(extra) != 1:
        fail("archive source has invalid policy or local path")
    source_path = Path(extra[0])
    if not source_path.is_file() or source_path.is_symlink():
        fail(name + " downloaded archive is not a plain file")
    digest = hashlib.sha256()
    with source_path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    actual_fetch_sha256 = digest.hexdigest()
    if actual_fetch_sha256 != archive_sha256:
        fail(name + " downloaded archive SHA-256 differs")
    actual_submodules_sha256 = None
    actual_head = None

record = {
    "archive": archive,
    "archive_sha256": archive_sha256,
    "checkout_head": actual_head,
    "fetched_archive_sha256": actual_fetch_sha256,
    "name": name,
    "origin": origin,
    "resolved_revision": resolved,
    "revision": revision,
    "source_kind": kind,
    "submodules": submodules,
    "submodules_sha256": actual_submodules_sha256,
}
target = Path(output_root) / "usr/local/share/tevless-build-provenance" / (name + ".json")
target.parent.mkdir(parents=True, exist_ok=True)
target.write_text(
    json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
PY
chmod 0555 /usr/local/bin/tevless-verify-source
EOF

RUN <<EOF
MESON_ARCHIVE=meson-1.12.0.tar.gz
curl --fail --location --proto '=https' --tlsv1.2 --output "$MESON_ARCHIVE" https://files.pythonhosted.org/packages/48/91/d58a3eb45ed54bf32b96806dd2f4efd407f7a9675953e15e8ef257840a0d/meson-1.12.0.tar.gz
tevless-verify-source upstream-archive meson https://files.pythonhosted.org/packages/48/91/d58a3eb45ed54bf32b96806dd2f4efd407f7a9675953e15e8ef257840a0d/meson-1.12.0.tar.gz 1.12.0 1.12.0 none - meson-1.12.0.tar.gz 88afe0c20e52030218924ac37d0c81c59b4b5f3ae3752c8c6d7470c7d365886c /tmp/tevless-build-tool-provenance "$MESON_ARCHIVE"
tar -xzf "$MESON_ARCHIVE"
(cd meson-1.12.0 && python3 setup.py install --prefix=/usr/local)

NINJA_ARCHIVE=ninja-1.13.0.tar.gz
curl --fail --location --proto '=https' --tlsv1.2 --output "$NINJA_ARCHIVE" https://files.pythonhosted.org/packages/43/73/79a0b22fc731989c708068427579e840a6cf4e937fe7ae5c5d0b7356ac22/ninja-1.13.0.tar.gz
tevless-verify-source upstream-archive ninja https://files.pythonhosted.org/packages/43/73/79a0b22fc731989c708068427579e840a6cf4e937fe7ae5c5d0b7356ac22/ninja-1.13.0.tar.gz 1.13.0 1.13.0 none - ninja-1.13.0.tar.gz 4a40ce995ded54d9dc24f8ea37ff3bf62ad192b547f6c7126e7e25045e76f978 /tmp/tevless-build-tool-provenance "$NINJA_ARCHIVE"
tar -xzf "$NINJA_ARCHIVE"
cmake -S ninja-1.13.0/ninja-upstream -B ninja-build -G 'Unix Makefiles' -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF
cmake --build ninja-build --parallel {{ JOBS }}
install -m 0755 ninja-build/ninja /usr/local/bin/ninja

rm -rf "$MESON_ARCHIVE" meson-1.12.0 "$NINJA_ARCHIVE" ninja-1.13.0 ninja-build /tmp/tevless-build-tool-provenance
EOF

WORKDIR /usr/src
ENV CC="ccache gcc"
ENV CXX="ccache g++"
ENV AR=gcc-ar
ENV RANLIB=gcc-ranlib
ENV NM=gcc-nm
ENV CFLAGS='{% if DEBUG %}-g -gdwarf64 -gz{% endif %} {% if MINSIZE %}-Os{% else %}-O3{% endif %} {% if LTO %}-flto=auto -ffat-lto-objects{% endif %} -pipe -fPIC -fno-strict-aliasing -fexceptions -fasynchronous-unwind-tables -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer -fhardened -Wno-hardened'
ENV CXXFLAGS=$CFLAGS
ENV LDFLAGS='-static-libstdc++ -static-libgcc -static-libasan -pthread -Wl,--push-state,--no-as-needed,-ldl,--pop-state -Wl,--as-needed -Wl,-z,muldefs'

ENV CCACHE_DIR=/var/cache/ccache
ENV CCACHE_UMASK=002
ENV CCACHE_COMPRESS=1
ENV CCACHE_MAXSIZE=20G

ENV CMAKE_GENERATOR=Ninja
ENV CMAKE_BUILD_TYPE=None
ENV CMAKE_BUILD_PARALLEL_LEVEL='{{ JOBS }}'

ENV SOURCE_DATE_EPOCH=1

RUN <<EOF
git init Implib.so
cd Implib.so
git remote add origin https://github.com/yugr/Implib.so.git
git fetch --depth=1 origin ecf7bb51a92a0fb16834c5b698570ab25f9f1d21
git reset --hard FETCH_HEAD
tevless-verify-source git implib-so https://github.com/yugr/Implib.so.git ecf7bb51a92a0fb16834c5b698570ab25f9f1d21 ecf7bb51a92a0fb16834c5b698570ab25f9f1d21 none e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 implib-so-ecf7bb51a92a.tar.xz b0ce77eb2b6fd46c2701378d6ba41b40e917bf620a37d5323f156c4552ffb5e4 / .

mkdir build
cd build

implib() {
	LIBFILE=$(basename $1)
	LIBNAME=$(basename $1 .so)
	../implib-gen.py -q $1
	gcc $CFLAGS -g0 -c -o $LIBFILE.tramp.o $LIBFILE.tramp.S
	gcc $CFLAGS -c -o $LIBFILE.init.o $LIBFILE.init.c
	ar rcs /usr/local/lib64/$LIBNAME.a $LIBFILE.tramp.o $LIBFILE.init.o
}

implib /usr/lib64/libgtk-3.so
implib /usr/lib64/libgdk-3.so
implib /usr/lib64/libgdk_pixbuf-2.0.so
implib /usr/lib64/libpango-1.0.so
implib /usr/lib64/libvdpau.so
implib /usr/lib64/libva-x11.so
implib /usr/lib64/libva-drm.so
implib /usr/lib64/libva.so
implib /usr/lib64/libEGL.so
implib /usr/lib64/libGLX.so
implib /usr/lib64/libOpenGL.so
implib /usr/lib64/libGL.so
implib /usr/lib64/libdrm.so
implib /usr/lib64/libudev.so
implib /usr/lib64/libwayland-egl.so
implib /usr/lib64/libwayland-cursor.so
implib /usr/lib64/libwayland-client.so
implib /usr/lib64/libwayland-server.so
implib /usr/lib64/libX11-xcb.so
implib /usr/lib64/libX11.so
implib /usr/lib64/libxcb.so

# Implib.so can only intercept functions, while the static libXext,
# libXfixes, libXdamage, libXcomposite, libXrender reference three Xlib
# threading data symbols. Define them with real locks (the always-on
# XInitThreads semantics of libX11 1.8+). The layout is private to this
# implementation: whether the real libX11 interposes these or keeps its
# own copies, each lock implementation only ever sees its own objects.
cat > libX11.locks.c <<'EOF2'
#include <pthread.h>

typedef struct _LockInfoRec {
	pthread_mutex_t mutex;
} LockInfoRec, *LockInfoPtr;

static LockInfoRec GlobalLock = { PTHREAD_MUTEX_INITIALIZER };

static void LockMutex(LockInfoPtr lock) {
	pthread_mutex_lock(&lock->mutex);
}

static void UnlockMutex(LockInfoPtr lock) {
	pthread_mutex_unlock(&lock->mutex);
}

LockInfoPtr _Xglobal_lock = &GlobalLock;
void (*_XLockMutex_fn)(LockInfoPtr) = LockMutex;
void (*_XUnlockMutex_fn)(LockInfoPtr) = UnlockMutex;
EOF2
gcc $CFLAGS -c -o libX11.locks.o libX11.locks.c
ar rs /usr/local/lib64/libX11.a libX11.locks.o

cd ../..
rm -rf Implib.so
EOF

FROM builder AS patches
RUN <<EOF
git init patches
cd patches
git remote add origin https://github.com/desktop-app/patches.git
git fetch --depth=1 origin 27efa67b60881c52b112cf924d705e573d03a0ab
git reset --hard FETCH_HEAD
tevless-verify-source git patches https://github.com/desktop-app/patches.git 27efa67b60881c52b112cf924d705e573d03a0ab 27efa67b60881c52b112cf924d705e573d03a0ab none e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 desktop-app-patches-27efa67b6088.tar.xz 6a0468aa10e9af5787c5cbb8b1a31284dda7cb2d9d56abe11ee056a2b3e68316 /usr/src/patches-cache .
rm -rf .git
EOF

FROM builder AS zlib
RUN --mount=type=cache,target=/var/cache/ccache <<EOF
git init zlib
cd zlib
git remote add origin https://github.com/madler/zlib.git
git fetch --depth=1 origin e3dc0a85b7032e98380dec011bc8f2c2ee0d8fca
git reset --hard FETCH_HEAD
tevless-verify-source git zlib https://github.com/madler/zlib.git e3dc0a85b7032e98380dec011bc8f2c2ee0d8fca e3dc0a85b7032e98380dec011bc8f2c2ee0d8fca none e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 zlib-e3dc0a85b703.tar.xz 991182b6405328c10d7c2294b2d66f6fb62180b27d9ca337065156a680ced6ad /usr/src/zlib-cache .
sed -i 's/Bool/BOOL/;s/ZLIB::ZLIBSTATIC/MINIZIP::minizipstatic/;s/ZLIB::ZLIB/MINIZIP::minizip/' \
	contrib/minizip/minizipConfig.cmake.in
sed -i '/DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"/s@}@}/minizip@' contrib/minizip/CMakeLists.txt
cmake -B build . \
	-DZLIB_BUILD_SHARED=OFF \
	-DZLIB_BUILD_TESTING=OFF \
	-DZLIB_BUILD_MINIZIP=ON \
	-DZLIB_MINIZIP_BUILD_SHARED=OFF \
	-DZLIB_MINIZIP_BUILD_TESTING=OFF
cmake --build build
DESTDIR=/usr/src/zlib-cache cmake --install build
cd ..
rm -rf zlib
EOF

FROM builder AS xz
RUN --mount=type=cache,target=/var/cache/ccache <<EOF
git clone -b v5.8.1 --depth=1 https://github.com/tukaani-project/xz.git
cd xz
tevless-verify-source git xz https://github.com/tukaani-project/xz.git v5.8.1 a522a226545730551f7e7c2685fab27cf567746c none e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 xz-v5.8.1.tar.xz 1b145451a9d119f94c85afc2432b1b89a28bfbca7315379fe8b28d3e757ec4c0 /usr/src/xz-cache .
cmake -B build .
cmake --build build
DESTDIR=/usr/src/xz-cache cmake --install build
cd ..
rm -rf xz
EOF

FROM builder AS abseil
RUN --mount=type=cache,target=/var/cache/ccache <<EOF
git clone -b 20250127.0 --depth=1 https://github.com/abseil/abseil-cpp.git
cd abseil-cpp
tevless-verify-source git abseil https://github.com/abseil/abseil-cpp.git 20250127.0 9ac7062b1860d895fb5a8cbf58c3e9ef8f674b5f none e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 abseil-20250127.0.tar.xz d6e063c4a2bc42d9d4f344841dae81bd8491596bb4856e8375614d2c7ef1ca7b /usr/src/abseil-cache .
cmake -B build . \
	-DABSL_BUILD_TESTING=OFF \
	-DABSL_ENABLE_INSTALL=ON \
	-DBUILD_SHARED_LIBS=OFF
cmake --build build
DESTDIR=/usr/src/abseil-cache cmake --install build
cd ..
rm -rf abseil-cpp
EOF

FROM builder AS protobuf
COPY --link --from=abseil /usr/src/abseil-cache /

RUN --mount=type=cache,target=/var/cache/ccache <<EOF
git clone -b v30.2 --depth=1 --recursive --shallow-submodules \
	https://github.com/protocolbuffers/protobuf.git
cd protobuf
tevless-verify-source git protobuf https://github.com/protocolbuffers/protobuf.git v30.2 43e1626812c1b543e56a7bec59dc09eb18248bd2 recursive e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 protobuf-v30.2-recursive.tar.xz 10d8b4eff44c989659f63dfb933ba9682554a8c10eb5dcbed8208a461e507856 /usr/src/protobuf-cache .
cmake -B build . \
	-Dprotobuf_BUILD_TESTS=OFF \
	-Dprotobuf_BUILD_PROTOBUF_BINARIES=ON \
	-Dprotobuf_BUILD_LIBPROTOC=ON \
	-Dprotobuf_LOCAL_DEPENDENCIES_ONLY=ON \
	-Dprotobuf_WITH_ZLIB=OFF
cmake --build build
DESTDIR=/usr/src/protobuf-cache cmake --install build
cd ..
rm -rf protobuf
EOF

FROM builder AS lcms2
RUN --mount=type=cache,target=/var/cache/ccache <<EOF
git clone -b lcms2.15 --depth=1 https://github.com/mm2/Little-CMS.git
cd Little-CMS
tevless-verify-source git lcms2 https://github.com/mm2/Little-CMS.git lcms2.15 d0752309ff93f62be246ee9bf18338107f30d485 none e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 lcms2-lcms2.15.tar.xz 81629ce04cbe49b2b84f1510a0e5276dbd2c2f608c3e8760b3ffeb1767607c9a /usr/src/lcms2-cache .
meson build --buildtype=plain --default-library=static
meson compile -C build
DESTDIR=/usr/src/lcms2-cache meson install -C build
cd ..
rm -rf Little-CMS
EOF

FROM builder AS brotli
RUN --mount=type=cache,target=/var/cache/ccache <<EOF
git clone -b v1.2.0 --depth=1 https://github.com/google/brotli.git
cd brotli
tevless-verify-source git brotli https://github.com/google/brotli.git v1.2.0 028fb5a23661f123017c060daa546b55cf4bde29 none e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 brotli-v1.2.0.tar.xz 32cd1c3169455fa1d4df42b63d9d7a181f7f41343550a80750cf44a035207a09 /usr/src/brotli-cache .
cmake -B build . -DBUILD_SHARED_LIBS=OFF -DBROTLI_DISABLE_TESTS=ON
cmake --build build
DESTDIR=/usr/src/brotli-cache cmake --install build
cd ..
rm -rf brotli
EOF

FROM builder AS highway
RUN --mount=type=cache,target=/var/cache/ccache <<EOF
git clone -b 1.4.0 --depth=1 https://github.com/google/highway.git
cd highway
tevless-verify-source git highway https://github.com/google/highway.git 1.4.0 2607d3b5b0113992fe84d3848859eae13b3b52c1 none e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 highway-1.4.0.tar.xz 234905c28b17622b29cffe8f301a0ba0ce3276b3cb23911317a527641753dd6c /usr/src/highway-cache .
cmake -B build . -DBUILD_TESTING=OFF -DHWY_ENABLE_CONTRIB=OFF -DHWY_ENABLE_EXAMPLES=OFF
cmake --build build
DESTDIR=/usr/src/highway-cache cmake --install build
cd ..
rm -rf highway
EOF

FROM builder AS mozjpeg
RUN --mount=type=cache,target=/var/cache/ccache <<EOF
git clone -b v4.1.5 --depth=1 https://github.com/mozilla/mozjpeg.git
cd mozjpeg
tevless-verify-source git mozjpeg https://github.com/mozilla/mozjpeg.git v4.1.5 6c9f0897afa1c2738d7222a0a9ab49e8b536a267 none e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 mozjpeg-v4.1.5.tar.xz ee2649f3988f6ec0a999161f684a13c0c46fd827b16751bea02d90edcd2ade90 /usr/src/mozjpeg-cache .
cmake -B build . \
	-DCMAKE_INSTALL_PREFIX=/usr/local \
	-DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
	-DENABLE_SHARED=OFF \
	-DWITH_JPEG8=ON \
	-DPNG_SUPPORTED=OFF
cmake --build build --parallel
DESTDIR=/usr/src/mozjpeg-cache cmake --install build
cd ..
rm -rf mozjpeg
EOF

FROM builder AS opus
RUN --mount=type=cache,target=/var/cache/ccache <<EOF
git clone -b v1.5.2 --depth=1 https://github.com/xiph/opus.git
cd opus
tevless-verify-source git opus https://github.com/xiph/opus.git v1.5.2 ddbe48383984d56acd9e1ab6a090c54ca6b735a6 none e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 opus-v1.5.2.tar.xz 8e84911bdab570bcdbfed63bc8fe91eaaab0b4353520937509443ceb58556889 /usr/src/opus-cache .
cmake -B build .
cmake --build build
DESTDIR=/usr/src/opus-cache cmake --install build
cd ..
rm -rf opus
EOF

FROM builder AS dav1d
RUN --mount=type=cache,target=/var/cache/ccache <<EOF
git clone -b 1.5.4 --depth=1 https://github.com/videolan/dav1d.git
cd dav1d
tevless-verify-source git dav1d https://github.com/videolan/dav1d.git 1.5.4 54706fc6bc0cdecab7e9593974a4039cc038fca7 none e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 dav1d-1.5.4.tar.xz 470bc8dc6b2bb996bd2801f840f029d072e51c2de9d84bcf1cd3c3d9bba53534 /usr/src/dav1d-cache .
meson build \
	--buildtype=plain \
	--default-library=static \
	-Denable_tools=false \
	-Denable_tests=false
meson compile -C build
DESTDIR=/usr/src/dav1d-cache meson install -C build
cd ..
rm -rf dav1d
EOF

FROM builder AS openh264
RUN --mount=type=cache,target=/var/cache/ccache <<EOF
git clone -b v2.6.0 --depth=1 https://github.com/cisco/openh264.git
cd openh264
tevless-verify-source git openh264 https://github.com/cisco/openh264.git v2.6.0 652bdb7719f30b52b08e506645a7322ff1b2cc6f none e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 openh264-v2.6.0.tar.xz 20eee231062e5b887c6fc6e85190d9fb14378346ad69755a6bed3ebe05e6fa74 /usr/src/openh264-cache .
meson build \
	--buildtype=plain \
	--default-library=static \
	--wrap-mode=nodownload \
	-Dtests=disabled
meson compile -C build
DESTDIR=/usr/src/openh264-cache meson install -C build
cd ..
rm -rf openh264
EOF

FROM builder AS de265
RUN --mount=type=cache,target=/var/cache/ccache <<EOF
git clone -b v1.1.1 --depth=1 https://github.com/strukturag/libde265.git
cd libde265
tevless-verify-source git libde265 https://github.com/strukturag/libde265.git v1.1.1 4dd701fffac01632ffd5cabc5ef10deb56accba1 none e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 libde265-v1.1.1.tar.xz fe09db6109af00cdf02945b97443374f70061369e4d0f1d50b8c37e371ab8c4a /usr/src/de265-cache .
cmake -B build . \
	-DCMAKE_BUILD_TYPE=None \
	-DBUILD_SHARED_LIBS=OFF \
	-DENABLE_DECODER=OFF \
	-DENABLE_SDL=OFF
cmake --build build
DESTDIR=/usr/src/de265-cache cmake --install build
cd ..
rm -rf libde265
EOF

FROM builder AS vpx
RUN --mount=type=cache,target=/var/cache/ccache <<EOF
git init libvpx
cd libvpx
git remote add origin https://github.com/webmproject/libvpx.git
git fetch --depth=1 origin 12f3a2ac603e8f10742105519e0cd03c3b8f71dd
git reset --hard FETCH_HEAD
tevless-verify-source git libvpx https://github.com/webmproject/libvpx.git 12f3a2ac603e8f10742105519e0cd03c3b8f71dd 12f3a2ac603e8f10742105519e0cd03c3b8f71dd none e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 libvpx-12f3a2ac603e.tar.xz a49fa60247d38d842c242d8b6899ae3584efd9ded3a64d8f09cd9abfaad42b75 /usr/src/vpx-cache .
CFLAGS="$CFLAGS -fno-lto" CXXFLAGS="$CXXFLAGS -fno-lto" ./configure \
	--disable-examples \
	--disable-unit-tests \
	--disable-tools \
	--disable-docs \
	--enable-vp8 \
	--enable-vp9 \
	--enable-webm-io \
	--size-limit=4096x4096
make HAVE_GNU_STRIP=no -j$(nproc)
make DESTDIR=/usr/src/vpx-cache install
cd ..
rm -rf libvpx
EOF

FROM builder AS webp
RUN --mount=type=cache,target=/var/cache/ccache <<EOF
git clone -b v1.6.0 --depth=1 https://github.com/webmproject/libwebp.git
cd libwebp
tevless-verify-source git libwebp https://github.com/webmproject/libwebp.git v1.6.0 4fa21912338357f89e4fd51cf2368325b59e9bd9 none e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 libwebp-v1.6.0.tar.xz e3a585aa0121d1a56922a6381c5de98d43635f0c530cd78a57d86967c682e192 /usr/src/webp-cache .
cmake -B build . \
	-DWEBP_BUILD_ANIM_UTILS=OFF \
	-DWEBP_BUILD_CWEBP=OFF \
	-DWEBP_BUILD_DWEBP=OFF \
	-DWEBP_BUILD_GIF2WEBP=OFF \
	-DWEBP_BUILD_IMG2WEBP=OFF \
	-DWEBP_BUILD_VWEBP=OFF \
	-DWEBP_BUILD_WEBPMUX=OFF \
	-DWEBP_BUILD_WEBPINFO=OFF \
	-DWEBP_BUILD_EXTRAS=OFF
cmake --build build
DESTDIR=/usr/src/webp-cache cmake --install build
cd ..
rm -rf libwebp
EOF

FROM builder AS avif
COPY --link --from=dav1d /usr/src/dav1d-cache /

RUN --mount=type=cache,target=/var/cache/ccache <<EOF
git clone -b v1.4.2 --depth=1 https://github.com/AOMediaCodec/libavif.git
cd libavif
tevless-verify-source git libavif https://github.com/AOMediaCodec/libavif.git v1.4.2 c5240fc79fe5c2407e10afd35f5505ef6333ea49 none e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 libavif-v1.4.2.tar.xz 367871c3919a30d7a903d36970793c662aea2a58225ba4fe4a14a4084d07de8e /usr/src/avif-cache .
cmake -B build . -DBUILD_SHARED_LIBS=OFF -DAVIF_CODEC_DAV1D=SYSTEM -DAVIF_LIBYUV=OFF
cmake --build build
DESTDIR=/usr/src/avif-cache cmake --install build
cd ..
rm -rf libavif
EOF

FROM builder AS heif
COPY --link --from=de265 /usr/src/de265-cache /

RUN --mount=type=cache,target=/var/cache/ccache <<EOF
git clone -b v1.23.1 --depth=1 https://github.com/strukturag/libheif.git
cd libheif
tevless-verify-source git libheif https://github.com/strukturag/libheif.git v1.23.1 2c4bbb54c2738d4a5efbbe3e5fa1d5d76bb88eb0 none e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 libheif-v1.23.1.tar.xz d85e09102b3bbc75c943fa3a20ffb3f3a0fe237b65fb64510a2030d74c2a4b1e /usr/src/heif-cache .
cmake -B build . \
	-DBUILD_SHARED_LIBS=OFF \
	-DBUILD_DOCUMENTATION=OFF \
	-DBUILD_TESTING=OFF \
	-DENABLE_PLUGIN_LOADING=OFF \
	-DWITH_X265=OFF \
	-DWITH_AOM_DECODER=OFF \
	-DWITH_AOM_ENCODER=OFF \
	-DWITH_X264=OFF \
	-DWITH_OpenH264_DECODER=OFF \
	-DWITH_RAV1E=OFF \
	-DWITH_RAV1E_PLUGIN=OFF \
	-DWITH_SvtEnc=OFF \
	-DWITH_SvtEnc_PLUGIN=OFF \
	-DWITH_DAV1D=OFF \
	-DWITH_LIBSHARPYUV=OFF \
	-DWITH_EXAMPLES=OFF
cmake --build build
DESTDIR=/usr/src/heif-cache cmake --install build
cd ..
rm -rf libheif
EOF

FROM builder AS jxl
COPY --link --from=lcms2 /usr/src/lcms2-cache /
COPY --link --from=brotli /usr/src/brotli-cache /
COPY --link --from=highway /usr/src/highway-cache /

RUN --mount=type=cache,target=/var/cache/ccache <<EOF
git clone -b v0.12.0 --depth=1 https://github.com/libjxl/libjxl.git
cd libjxl
tevless-verify-source git libjxl https://github.com/libjxl/libjxl.git v0.12.0 a7a9c787341cf703dede03c2009fa460cae5e5df none e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 libjxl-v0.12.0.tar.xz 1b4f0a230f0adccfaf425504f9646be4282ad97659e3df44353de7df714be31e /usr/src/jxl-cache .
cmake -B build . \
	-DBUILD_SHARED_LIBS=OFF \
	-DBUILD_TESTING=OFF \
	-DJPEGXL_ENABLE_DEVTOOLS=OFF \
	-DJPEGXL_ENABLE_TOOLS=OFF \
	-DJPEGXL_ENABLE_DOXYGEN=OFF \
	-DJPEGXL_ENABLE_MANPAGES=OFF \
	-DJPEGXL_ENABLE_BENCHMARK=OFF \
	-DJPEGXL_ENABLE_EXAMPLES=OFF \
	-DJPEGXL_ENABLE_JNI=OFF \
	-DJPEGXL_ENABLE_SJPEG=OFF \
	-DJPEGXL_ENABLE_OPENEXR=OFF \
	-DJPEGXL_ENABLE_SKCMS=OFF
cmake --build build
export DESTDIR=/usr/src/jxl-cache
cmake --install build
sed -i 's/-lstdc++//' $DESTDIR/usr/local/lib64/pkgconfig/libjxl*.pc
cd ..
rm -rf libjxl
EOF

FROM builder AS rnnoise
RUN --mount=type=cache,target=/var/cache/ccache <<EOF
git clone -b v0.2 --depth=1 https://github.com/xiph/rnnoise.git
cd rnnoise
tevless-verify-source git rnnoise https://github.com/xiph/rnnoise.git v0.2 904a876dce1f9ab8860c0a5000ed151f9f6eef58 none e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 rnnoise-v0.2.tar.xz 90d282be22ef304d2efd96b9c88b712ecef8610dd89cdd32fc2e12d3e3ecf68e /usr/src/rnnoise-cache .
./autogen.sh
./configure --enable-static --disable-shared
make -j$(nproc)
make DESTDIR=/usr/src/rnnoise-cache install
cd ..
rm -rf rnnoise
EOF

FROM builder AS xcb-proto
RUN --mount=type=cache,target=/var/cache/ccache <<EOF
git clone -b xcb-proto-1.16.0 --depth=1 https://github.com/gitlab-freedesktop-mirrors/xcbproto.git
cd xcbproto
tevless-verify-source git xcbproto https://github.com/gitlab-freedesktop-mirrors/xcbproto.git xcb-proto-1.16.0 98eeebfc2d7db5377b85437418fb942ea30ffc0d none e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 xcbproto-1.16.0.tar.xz 3d10b90b269eff32e6884c95dccbffadc73867d1ae7d9457c8704501cbca0710 /usr/src/xcb-proto-cache .
./autogen.sh
make -j$(nproc)
make DESTDIR=/usr/src/xcb-proto-cache install
cd ..
rm -rf xcbproto
EOF

FROM builder AS xcb
COPY --link --from=xcb-proto /usr/src/xcb-proto-cache /

RUN --mount=type=cache,target=/var/cache/ccache <<EOF
git clone -b libxcb-1.16 --depth=1 https://github.com/gitlab-freedesktop-mirrors/libxcb.git
cd libxcb
tevless-verify-source git libxcb https://github.com/gitlab-freedesktop-mirrors/libxcb.git libxcb-1.16 cc4b93c9cd93bad15b7106747b0213e4b9c53a1c none e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 libxcb-libxcb-1.16.tar.xz fe5149cfd19cf509b97d1c18e5a20a3e1160e8d6e2cfb9b31d4368b3807486e0 /usr/src/xcb-cache .
./autogen.sh --enable-static --disable-shared
make -j$(nproc)
export DESTDIR=/usr/src/xcb-cache
make install
rm $DESTDIR/usr/local/lib/{libxcb.{,l}a,pkgconfig/xcb.pc}
cd ..
rm -rf libxcb
EOF

FROM builder AS xcb-wm
RUN --mount=type=cache,target=/var/cache/ccache <<EOF
git clone -b xcb-util-wm-0.4.2 --depth=1 --recursive --shallow-submodules \
	https://github.com/gitlab-freedesktop-mirrors/libxcb-wm.git
cd libxcb-wm
tevless-verify-source git libxcb-wm https://github.com/gitlab-freedesktop-mirrors/libxcb-wm.git xcb-util-wm-0.4.2 0c6681e465c9cc7b1fbb60778ba1eaa61ab01a14 recursive 46bb9066a5806fbf8df66e5d247bcb9fbb5aab7081dbf861e0412e43be6b1c5b libxcb-wm-0.4.2.tar.xz 01155949c0de8e326e33bf47c5c8fdc1562596a527322ace62e9819105495739 /usr/src/xcb-wm-cache .
./autogen.sh --enable-static --disable-shared
make -j$(nproc)
make DESTDIR=/usr/src/xcb-wm-cache install
cd ..
rm -rf libxcb-wm
EOF

FROM builder AS xcb-util
RUN --mount=type=cache,target=/var/cache/ccache <<EOF
git clone -b xcb-util-0.4.1-gitlab --depth=1 --recursive --shallow-submodules \
	https://github.com/gitlab-freedesktop-mirrors/libxcb-util.git
cd libxcb-util
tevless-verify-source git libxcb-util https://github.com/gitlab-freedesktop-mirrors/libxcb-util.git xcb-util-0.4.1-gitlab bffd8df1725c0fae9105a097e75b466e2f49d7bd recursive 46bb9066a5806fbf8df66e5d247bcb9fbb5aab7081dbf861e0412e43be6b1c5b libxcb-util-0.4.1-gitlab.tar.xz 81c8a1b0fa702d14b53be8383ba4f3442ffcc93ad5d419654dd4cbf64d0d1e94 /usr/src/xcb-util-cache .
./autogen.sh --enable-static --disable-shared
make -j$(nproc)
make DESTDIR=/usr/src/xcb-util-cache install
cd ..
rm -rf libxcb-util
EOF

FROM builder AS xcb-image
COPY --link --from=xcb-util /usr/src/xcb-util-cache /

RUN --mount=type=cache,target=/var/cache/ccache <<EOF
git clone -b xcb-util-image-0.4.1-gitlab --depth=1 --recursive --shallow-submodules \
	https://github.com/gitlab-freedesktop-mirrors/libxcb-image.git
cd libxcb-image
tevless-verify-source git libxcb-image https://github.com/gitlab-freedesktop-mirrors/libxcb-image.git xcb-util-image-0.4.1-gitlab 1abfc17b1e08e46dbdf34b4ef36097a8c307a8ec recursive 46bb9066a5806fbf8df66e5d247bcb9fbb5aab7081dbf861e0412e43be6b1c5b libxcb-image-0.4.1-gitlab.tar.xz db9e4706595ce4295d275f2d09a31ca37a80ada3390d93de71468243f122afdf /usr/src/xcb-image-cache .
./autogen.sh --enable-static --disable-shared
make -j$(nproc)
make DESTDIR=/usr/src/xcb-image-cache install
cd ..
rm -rf libxcb-image
EOF

FROM builder AS xcb-keysyms
RUN --mount=type=cache,target=/var/cache/ccache <<EOF
git init libxcb-keysyms
cd libxcb-keysyms
git remote add origin https://github.com/gitlab-freedesktop-mirrors/libxcb-keysyms.git
git fetch --depth=1 origin ef5cb393d27511ba511c68a54f8ff7b9aab4a384
git reset --hard FETCH_HEAD
git submodule update --init --recursive --depth=1
tevless-verify-source git libxcb-keysyms https://github.com/gitlab-freedesktop-mirrors/libxcb-keysyms.git ef5cb393d27511ba511c68a54f8ff7b9aab4a384 ef5cb393d27511ba511c68a54f8ff7b9aab4a384 recursive 46bb9066a5806fbf8df66e5d247bcb9fbb5aab7081dbf861e0412e43be6b1c5b libxcb-keysyms-ef5cb393d275.tar.xz f9d02d33c8b127b71d42fa1043a91c5f502b5ac957b68749721e2c00ba27f452 /usr/src/xcb-keysyms-cache .
./autogen.sh --enable-static --disable-shared
make -j$(nproc)
make DESTDIR=/usr/src/xcb-keysyms-cache install
cd ..
rm -rf libxcb-keysyms
EOF

FROM builder AS xcb-render-util
RUN --mount=type=cache,target=/var/cache/ccache <<EOF
git init libxcb-render-util
cd libxcb-render-util
git remote add origin https://github.com/gitlab-freedesktop-mirrors/libxcb-render-util.git
git fetch --depth=1 origin 5ad9853d6ddcac394d42dd2d4e34436b5db9da39
git reset --hard FETCH_HEAD
git submodule update --init --recursive --depth=1
tevless-verify-source git libxcb-render-util https://github.com/gitlab-freedesktop-mirrors/libxcb-render-util.git 5ad9853d6ddcac394d42dd2d4e34436b5db9da39 5ad9853d6ddcac394d42dd2d4e34436b5db9da39 recursive 46bb9066a5806fbf8df66e5d247bcb9fbb5aab7081dbf861e0412e43be6b1c5b libxcb-render-util-5ad9853d6ddc.tar.xz 7ceda23756b2287bb4aa4d6cf12ea4b2d3a87559383324532d3059a0e406dbae /usr/src/xcb-render-util-cache .
./autogen.sh --enable-static --disable-shared
make -j$(nproc)
make DESTDIR=/usr/src/xcb-render-util-cache install
cd ..
rm -rf libxcb-render-util
EOF

FROM builder AS xcb-cursor
COPY --link --from=xcb-util /usr/src/xcb-util-cache /
COPY --link --from=xcb-image /usr/src/xcb-image-cache /
COPY --link --from=xcb-render-util /usr/src/xcb-render-util-cache /

RUN --mount=type=cache,target=/var/cache/ccache <<EOF
git init libxcb-cursor
cd libxcb-cursor
git remote add origin https://github.com/gitlab-freedesktop-mirrors/libxcb-cursor.git
git fetch --depth=1 origin 4929f6051658ba5424b41703a1fb63f9db896065
git reset --hard FETCH_HEAD
git submodule update --init --recursive --depth=1
tevless-verify-source git libxcb-cursor https://github.com/gitlab-freedesktop-mirrors/libxcb-cursor.git 4929f6051658ba5424b41703a1fb63f9db896065 4929f6051658ba5424b41703a1fb63f9db896065 recursive 46bb9066a5806fbf8df66e5d247bcb9fbb5aab7081dbf861e0412e43be6b1c5b libxcb-cursor-4929f6051658.tar.xz e33249fd317437a4f0090f885d933acc4128ed75e003aab743a3b0c976742051 /usr/src/xcb-cursor-cache .
./autogen.sh \
	--enable-static \
	--disable-shared \
	--with-cursorpath='~/.local/share/icons:~/.icons:/usr/share/icons:/usr/share/pixmaps'
make -j$(nproc)
make DESTDIR=/usr/src/xcb-cursor-cache install
cd ..
rm -rf libxcb-cursor
EOF

FROM builder AS xext
RUN --mount=type=cache,target=/var/cache/ccache <<EOF
git clone -b libXext-1.3.5 --depth=1 https://github.com/gitlab-freedesktop-mirrors/libxext.git
cd libxext
tevless-verify-source git libxext https://github.com/gitlab-freedesktop-mirrors/libxext.git libXext-1.3.5 67e82cc395f44faddd83ec3d0d21624fe91c6fc0 none e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 libxext-1.3.5.tar.xz 8ae1fe94e56c52ddaf5df5d246f11a1959db7a0cdecf0d76d26beb17e496d7fb /usr/src/xext-cache .
./autogen.sh --enable-static --disable-shared
make -j$(nproc)
make DESTDIR=/usr/src/xext-cache install
cd ..
rm -rf libxext
EOF

FROM builder AS xtst
RUN --mount=type=cache,target=/var/cache/ccache <<EOF
git clone -b libXtst-1.2.4 --depth=1 https://github.com/gitlab-freedesktop-mirrors/libxtst.git
cd libxtst
tevless-verify-source git libxtst https://github.com/gitlab-freedesktop-mirrors/libxtst.git libXtst-1.2.4 99b89c3bcb0ebb0b6dd86bfdc9d276715eaea889 none e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 libxtst-1.2.4.tar.xz 637dc3ac89b2c5118f54865b3c636a7a4c9c5d5b237a650f37925d80403bec5e /usr/src/xtst-cache .
./autogen.sh --enable-static --disable-shared
make -j$(nproc)
make DESTDIR=/usr/src/xtst-cache install
cd ..
rm -rf libxtst
EOF

FROM builder AS xfixes
RUN --mount=type=cache,target=/var/cache/ccache <<EOF
git clone -b libXfixes-5.0.3 --depth=1 https://github.com/gitlab-freedesktop-mirrors/libxfixes.git
cd libxfixes
tevless-verify-source git libxfixes https://github.com/gitlab-freedesktop-mirrors/libxfixes.git libXfixes-5.0.3 84df9cb81cc31bbed27ba241a23ae04f61da57db none e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 libxfixes-5.0.3.tar.xz 215b9c1e39da4eb47b5b87a77bd18e0a3a914aa9aa2d92392466259030fe9632 /usr/src/xfixes-cache .
./autogen.sh --enable-static --disable-shared
make -j$(nproc)
make DESTDIR=/usr/src/xfixes-cache install
cd ..
rm -rf libxfixes
EOF

FROM builder AS xv
COPY --link --from=xext /usr/src/xext-cache /

RUN --mount=type=cache,target=/var/cache/ccache <<EOF
git clone -b libXv-1.0.12 --depth=1 https://github.com/gitlab-freedesktop-mirrors/libxv.git
cd libxv
tevless-verify-source git libxv https://github.com/gitlab-freedesktop-mirrors/libxv.git libXv-1.0.12 d419928942dbf1897c9627475aa4a2828a81240f none e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 libxv-1.0.12.tar.xz fd6e0cbd37d14d9c600cc16f77232317d03faa938d8f8975963839ec0f2d5b63 /usr/src/xv-cache .
./autogen.sh --enable-static --disable-shared
make -j$(nproc)
make DESTDIR=/usr/src/xv-cache install
cd ..
rm -rf libxv
EOF

FROM builder AS xrandr
RUN --mount=type=cache,target=/var/cache/ccache <<EOF
git clone -b libXrandr-1.5.3 --depth=1 https://github.com/gitlab-freedesktop-mirrors/libxrandr.git
cd libxrandr
tevless-verify-source git libxrandr https://github.com/gitlab-freedesktop-mirrors/libxrandr.git libXrandr-1.5.3 3387129532899eaeee3477a2d92fa662d7292a84 none e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 libxrandr-1.5.3.tar.xz 9b9e98a1b804fc25a83623bdef20b271b1f4e09840f5c6407bf1469d1df9e907 /usr/src/xrandr-cache .
./autogen.sh --enable-static --disable-shared
make -j$(nproc)
make DESTDIR=/usr/src/xrandr-cache install
cd ..
rm -rf libxrandr
EOF

FROM builder AS xrender
RUN --mount=type=cache,target=/var/cache/ccache <<EOF
git clone -b libXrender-0.9.11 --depth=1 https://github.com/gitlab-freedesktop-mirrors/libxrender.git
cd libxrender
tevless-verify-source git libxrender https://github.com/gitlab-freedesktop-mirrors/libxrender.git libXrender-0.9.11 e5e23272394c90731debd7e18dd167e8c25b5c15 none e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 libxrender-0.9.11.tar.xz 6094ba7a9105c9c2204d9439b6f6b3132a36d7b3de575c2bde4c5fafe40b231e /usr/src/xrender-cache .
./autogen.sh --enable-static --disable-shared
make -j$(nproc)
make DESTDIR=/usr/src/xrender-cache install
cd ..
rm -rf libxrender
EOF

FROM builder AS xdamage
RUN --mount=type=cache,target=/var/cache/ccache <<EOF
git clone -b libXdamage-1.1.6 --depth=1 https://github.com/gitlab-freedesktop-mirrors/libxdamage.git
cd libxdamage
tevless-verify-source git libxdamage https://github.com/gitlab-freedesktop-mirrors/libxdamage.git libXdamage-1.1.6 1f20df4fd7c132f55e924dc5ec3f270cd54704d0 none e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 libxdamage-1.1.6.tar.xz a2a3fba31e2e8ea1a1d1d2cb6a8dc46f1dd338bc3a21ae5b61c76a766df17723 /usr/src/xdamage-cache .
./autogen.sh --enable-static --disable-shared
make -j$(nproc)
make DESTDIR=/usr/src/xdamage-cache install
cd ..
rm -rf libxdamage
EOF

FROM builder AS xcomposite
RUN --mount=type=cache,target=/var/cache/ccache <<EOF
git clone -b libXcomposite-0.4.6 --depth=1 \
	https://github.com/gitlab-freedesktop-mirrors/libxcomposite.git
cd libxcomposite
tevless-verify-source git libxcomposite https://github.com/gitlab-freedesktop-mirrors/libxcomposite.git libXcomposite-0.4.6 cecff847395deb553b6331f31776f9cbfc809add none e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 libxcomposite-0.4.6.tar.xz 4a9d49bbfb5864afb8270d31d62f676c1f7e17ec66758b32e8962105327bcef8 /usr/src/xcomposite-cache .
./autogen.sh --enable-static --disable-shared
make -j$(nproc)
make DESTDIR=/usr/src/xcomposite-cache install
cd ..
rm -rf libxcomposite
EOF

FROM builder AS nv-codec-headers
RUN --mount=type=cache,target=/var/cache/ccache <<EOF
git clone -b n12.1.14.0 --depth=1 https://github.com/FFmpeg/nv-codec-headers.git
cd nv-codec-headers
tevless-verify-source git nv-codec-headers https://github.com/FFmpeg/nv-codec-headers.git n12.1.14.0 1889e62e2d35ff7aa9baca2bceb14f053785e6f1 none e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 nv-codec-headers-n12.1.14.0.tar.xz c6fdf4acd8a9fbf27b67960b99b983e80a7d8652ee8c883756642ab021ac6f24 /usr/src/nv-codec-headers-cache .
cd ..
make -C nv-codec-headers DESTDIR=/usr/src/nv-codec-headers-cache install
rm -rf nv-codec-headers
EOF

FROM builder AS ffmpeg
COPY --link --from=opus /usr/src/opus-cache /
COPY --link --from=openh264 /usr/src/openh264-cache /
COPY --link --from=dav1d /usr/src/dav1d-cache /
COPY --link --from=vpx /usr/src/vpx-cache /
COPY --link --from=xext /usr/src/xext-cache /
COPY --link --from=xv /usr/src/xv-cache /
COPY --link --from=nv-codec-headers /usr/src/nv-codec-headers-cache /

RUN --mount=type=cache,target=/var/cache/ccache <<EOF
git clone -b n6.1.6 --depth=1 https://github.com/FFmpeg/FFmpeg.git
cd FFmpeg
tevless-verify-source git ffmpeg https://github.com/FFmpeg/FFmpeg.git n6.1.6 f1e3a2bf7a2f2cde936d1ed97f09a26853d20125 none e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 ffmpeg-n6.1.6.tar.xz 36b53c89e86bbf220ba2b962e9ae72d0a9768b364d12d59de6233a33c153b281 /usr/src/ffmpeg-cache .
./configure \
	--extra-cflags="-fno-lto -DCONFIG_SAFE_BITSTREAM_READER=1" \
	--extra-cxxflags="-fno-lto -DCONFIG_SAFE_BITSTREAM_READER=1" \
	--extra-ldflags="-Wl,--push-state,--no-as-needed,-lstdc++,--pop-state" \
	--disable-debug \
	--disable-programs \
	--disable-doc \
	--disable-network \
	--disable-autodetect \
	--disable-everything \
{%- if MINSIZE %}
	--enable-small \
{%- endif %}
	--enable-libdav1d \
	--enable-libopenh264 \
	--enable-libopus \
	--enable-libvpx \
	--enable-vaapi \
	--enable-vdpau \
	--enable-xlib \
	--enable-libdrm \
	--enable-ffnvcodec \
	--enable-nvdec \
	--enable-cuvid \
	--enable-protocol=file \
	--enable-hwaccel=av1_vaapi \
	--enable-hwaccel=av1_nvdec \
	--enable-hwaccel=h264_vaapi \
	--enable-hwaccel=h264_vdpau \
	--enable-hwaccel=h264_nvdec \
	--enable-hwaccel=hevc_vaapi \
	--enable-hwaccel=hevc_vdpau \
	--enable-hwaccel=hevc_nvdec \
	--enable-hwaccel=mpeg2_vaapi \
	--enable-hwaccel=mpeg2_vdpau \
	--enable-hwaccel=mpeg2_nvdec \
	--enable-hwaccel=mpeg4_vaapi \
	--enable-hwaccel=mpeg4_vdpau \
	--enable-hwaccel=mpeg4_nvdec \
	--enable-hwaccel=vp8_vaapi \
	--enable-hwaccel=vp8_nvdec \
	--enable-decoder=aac \
	--enable-decoder=aac_fixed \
	--enable-decoder=aac_latm \
	--enable-decoder=aasc \
	--enable-decoder=ac3 \
	--enable-decoder=alac \
	--enable-decoder=av1 \
	--enable-decoder=av1_cuvid \
	--enable-decoder=eac3 \
	--enable-decoder=flac \
	--enable-decoder=gif \
	--enable-decoder=h264 \
	--enable-decoder=hevc \
	--enable-decoder=libdav1d \
	--enable-decoder=libvpx_vp8 \
	--enable-decoder=libvpx_vp9 \
	--enable-decoder=mp1 \
	--enable-decoder=mp1float \
	--enable-decoder=mp2 \
	--enable-decoder=mp2float \
	--enable-decoder=mp3 \
	--enable-decoder=mp3adu \
	--enable-decoder=mp3adufloat \
	--enable-decoder=mp3float \
	--enable-decoder=mp3on4 \
	--enable-decoder=mp3on4float \
	--enable-decoder=mpeg4 \
	--enable-decoder=msmpeg4v2 \
	--enable-decoder=msmpeg4v3 \
	--enable-decoder=opus \
	--enable-decoder=pcm_alaw \
	--enable-decoder=pcm_f32be \
	--enable-decoder=pcm_f32le \
	--enable-decoder=pcm_f64be \
	--enable-decoder=pcm_f64le \
	--enable-decoder=pcm_lxf \
	--enable-decoder=pcm_mulaw \
	--enable-decoder=pcm_s16be \
	--enable-decoder=pcm_s16be_planar \
	--enable-decoder=pcm_s16le \
	--enable-decoder=pcm_s16le_planar \
	--enable-decoder=pcm_s24be \
	--enable-decoder=pcm_s24daud \
	--enable-decoder=pcm_s24le \
	--enable-decoder=pcm_s24le_planar \
	--enable-decoder=pcm_s32be \
	--enable-decoder=pcm_s32le \
	--enable-decoder=pcm_s32le_planar \
	--enable-decoder=pcm_s64be \
	--enable-decoder=pcm_s64le \
	--enable-decoder=pcm_s8 \
	--enable-decoder=pcm_s8_planar \
	--enable-decoder=pcm_u16be \
	--enable-decoder=pcm_u16le \
	--enable-decoder=pcm_u24be \
	--enable-decoder=pcm_u24le \
	--enable-decoder=pcm_u32be \
	--enable-decoder=pcm_u32le \
	--enable-decoder=pcm_u8 \
	--enable-decoder=pcm_zork \
	--enable-decoder=vorbis \
	--enable-decoder=vp8 \
	--enable-decoder=wavpack \
	--enable-decoder=wmalossless \
	--enable-decoder=wmapro \
	--enable-decoder=wmav1 \
	--enable-decoder=wmav2 \
	--enable-decoder=wmavoice \
	--enable-encoder=aac \
	--enable-encoder=libopenh264 \
	--enable-encoder=libopus \
	--enable-encoder=pcm_s16le \
	--enable-filter=atempo \
	--enable-parser=aac \
	--enable-parser=aac_latm \
	--enable-parser=flac \
	--enable-parser=gif \
	--enable-parser=h264 \
	--enable-parser=hevc \
	--enable-parser=mpeg4video \
	--enable-parser=mpegaudio \
	--enable-parser=opus \
	--enable-parser=vorbis \
	--enable-demuxer=aac \
	--enable-demuxer=flac \
	--enable-demuxer=gif \
	--enable-demuxer=h264 \
	--enable-demuxer=hevc \
	--enable-demuxer=matroska \
	--enable-demuxer=m4v \
	--enable-demuxer=mov \
	--enable-demuxer=mp3 \
	--enable-demuxer=ogg \
	--enable-demuxer=wav \
	--enable-muxer=mp4 \
	--enable-muxer=ogg \
	--enable-muxer=opus \
	--enable-muxer=wav
make -j$(nproc)
make DESTDIR=/usr/src/ffmpeg-cache install
cd ..
rm -rf ffmpeg
EOF

FROM builder AS pipewire
RUN --mount=type=cache,target=/var/cache/ccache <<EOF
git clone -b 0.3.62 --depth=1 https://github.com/PipeWire/pipewire.git
cd pipewire
tevless-verify-source git pipewire https://github.com/PipeWire/pipewire.git 0.3.62 3a443b4e1c9730675c7de0453a6279ab9ee263fd none e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 pipewire-0.3.62.tar.xz c9ee5e8fcf2e5d04ee41d2448dc3bf7ac0ec9a1e65c70ec3392c24cc76a8c999 /usr/src/pipewire-cache .
meson build \
	--buildtype=plain \
	-Dtests=disabled \
	-Dexamples=disabled \
	-Dspa-plugins=disabled \
	-Dsession-managers=
meson compile -C build
DESTDIR=/usr/src/pipewire-cache meson install -C build
cd ..
rm -rf pipewire
EOF

FROM builder AS openal
COPY --link --from=pipewire /usr/src/pipewire-cache /

RUN --mount=type=cache,target=/var/cache/ccache <<EOF
git clone -b 1.25.2 --depth=1 https://github.com/kcat/openal-soft.git
cd openal-soft
tevless-verify-source git openal-soft https://github.com/kcat/openal-soft.git 1.25.2 b2c48f7718ef3fcf67921a8b6534c4914e328970 none e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 openal-soft-1.25.2.tar.xz e1e1ef6a97944239d55d836581b118720b687ff4f82bde720788cbd2e09ca345 /usr/src/openal-cache .
cmake -B build . \
	-DCMAKE_DISABLE_FIND_PACKAGE_DBus1=ON \
	-DLIBTYPE:STRING=STATIC \
	-DALSOFT_EXAMPLES=OFF \
	-DALSOFT_UTILS=OFF \
	-DALSOFT_INSTALL_CONFIG=OFF
cmake --build build
DESTDIR=/usr/src/openal-cache cmake --install build
cd ..
rm -rf openal-soft
EOF

FROM builder AS openssl
RUN --mount=type=cache,target=/var/cache/ccache <<EOF
git clone -b openssl-3.2.1 --depth=1 https://github.com/openssl/openssl.git
cd openssl
tevless-verify-source git openssl https://github.com/openssl/openssl.git openssl-3.2.1 a7e992847de83aa36be0c399c89db3fb827b0be2 none e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 openssl-3.2.1.tar.xz 33c82dc528130dfd79cfc05e9f7e2a472304da05531e85d2f757ad651a551087 /usr/src/openssl-cache .
sed -i 's/$cmd $cmdflags -c -o/$cmd $cmdflags -g0 -c -o/' Configurations/unix-Makefile.tmpl
./config --openssldir=/etc/ssl no-shared no-tests no-dso
make -j$(nproc)
make DESTDIR=/usr/src/openssl-cache install_sw
cd ..
rm -rf openssl
EOF

FROM builder AS xkbcommon
COPY --link --from=xcb /usr/src/xcb-cache /

RUN --mount=type=cache,target=/var/cache/ccache <<EOF
git clone -b xkbcommon-1.6.0 --depth=1 https://github.com/xkbcommon/libxkbcommon.git
cd libxkbcommon
tevless-verify-source git xkbcommon https://github.com/xkbcommon/libxkbcommon.git xkbcommon-1.6.0 d2a08f761c796733e42fac4099f5c38d443e88e1 none e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 xkbcommon-1.6.0.tar.xz 40a2da6ab155b7615f4308cc7bc7cd8fc9208fa8e2ca1c86e095977e43af34d7 /usr/src/xkbcommon-cache .
meson build \
	--buildtype=plain \
	--default-library=static \
	-Denable-docs=false \
	-Denable-wayland=false \
	-Denable-xkbregistry=false \
	-Dxkb-config-root=/usr/share/X11/xkb \
	-Dxkb-config-extra-path=/etc/xkb \
	-Dx-locale-root=/usr/share/X11/locale
meson compile -C build
DESTDIR=/usr/src/xkbcommon-cache meson install -C build
cd ..
rm -rf libxkbcommon
EOF

FROM patches AS qt
COPY --link --from=zlib /usr/src/zlib-cache /
COPY --link --from=lcms2 /usr/src/lcms2-cache /
COPY --link --from=mozjpeg /usr/src/mozjpeg-cache /
COPY --link --from=webp /usr/src/webp-cache /
COPY --link --from=xcb /usr/src/xcb-cache /
COPY --link --from=xcb-wm /usr/src/xcb-wm-cache /
COPY --link --from=xcb-util /usr/src/xcb-util-cache /
COPY --link --from=xcb-image /usr/src/xcb-image-cache /
COPY --link --from=xcb-keysyms /usr/src/xcb-keysyms-cache /
COPY --link --from=xcb-render-util /usr/src/xcb-render-util-cache /
COPY --link --from=xcb-cursor /usr/src/xcb-cursor-cache /
COPY --link --from=openssl /usr/src/openssl-cache /
COPY --link --from=xkbcommon /usr/src/xkbcommon-cache /

RUN --mount=type=cache,target=/var/cache/ccache <<EOF
QT=6.11.1
git clone -b v$QT --depth=1 https://github.com/qt/qt5.git
cd qt5
git submodule update --init --recursive --depth=1 \
	qtbase qtdeclarative qtwayland qtimageformats qtsvg qtshadertools
tevless-verify-source git qt https://github.com/qt/qt5.git 'v6.11.1 (qtbase, qtdeclarative, qtwayland, qtimageformats, qtsvg, qtshadertools)' bfde7b892add48396756dc44a3e3fa03d98c5710 selected b5eb6cdbad7eb1d0675235c740cd343dac5ebe40e0ee52e4496a0017d4debda1 qt-6.11.1-selected-recursive.tar.xz e7be0b21ca2139490d282826e845ab57aaab5ddcc724f1cf57b2967d7b48ef60 /usr/src/qt-cache . qtbase qtdeclarative qtwayland qtimageformats qtsvg qtshadertools
find $PWD/../patches/qtbase_$QT -type f -print0 | sort -z | xargs -r0 git -C qtbase apply
find $PWD/../patches/qtwayland_$QT -type f -print0 | sort -z | xargs -r0 git -C qtwayland apply
cmake -B build . \
	-DCMAKE_INSTALL_PREFIX=/usr/local \
	-DBUILD_SHARED_LIBS=OFF \
	-DBUILD_WITH_PCH=OFF \
{%- if ASAN %}
	-DFEATURE_sanitize_address=ON \
{%- endif %}
	-DQT_QPA_PLATFORMS="wayland;xcb" \
	-DINPUT_libpng=qt \
	-DINPUT_harfbuzz=qt \
	-DINPUT_pcre=qt \
	-DFEATURE_icu=OFF \
	-DFEATURE_xcb_sm=OFF \
	-DFEATURE_eglfs=OFF \
	-DINPUT_dbus=runtime \
	-DINPUT_openssl=linked
cmake --build build
DESTDIR=/usr/src/qt-cache cmake --install build
cd ..
rm -rf qt5
EOF

FROM builder AS boost
RUN --mount=type=cache,target=/var/cache/ccache <<EOF
BOOST_ARCHIVE=boost_1_90_0.tar.gz
curl --fail --location --proto '=https' --tlsv1.2 --output "$BOOST_ARCHIVE" https://archives.boost.io/release/1.90.0/source/boost_1_90_0.tar.gz
tevless-verify-source upstream-archive boost https://archives.boost.io/release/1.90.0/source/boost_1_90_0.tar.gz 1.90.0 1.90.0 none - boost-1.90.0.tar.gz 5e93d582aff26868d581a52ae78c7d8edf3f3064742c6e77901a1f18a437eea9 /usr/src/boost-cache "$BOOST_ARCHIVE"
tar -xzf "$BOOST_ARCHIVE"
cd boost_1_90_0
./bootstrap.sh --prefix=/usr/src/boost-cache/usr/local --with-libraries=regex
./b2 release link=static cflags="$CFLAGS" cxxflags="$CXXFLAGS" linkflags="$LDFLAGS" -j$(nproc) install
cd ..
rm -rf boost_*
EOF

FROM builder AS breakpad
RUN --mount=type=cache,target=/var/cache/ccache <<EOF
git init breakpad
cd breakpad
git remote add origin https://chromium.googlesource.com/breakpad/breakpad.git
git fetch --depth=1 origin 9aebd3d8ef5a246deb2c929b5666aaba160ebce6
git reset --hard FETCH_HEAD
tevless-verify-source git breakpad https://chromium.googlesource.com/breakpad/breakpad.git 9aebd3d8ef5a246deb2c929b5666aaba160ebce6 9aebd3d8ef5a246deb2c929b5666aaba160ebce6 none e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 breakpad-9aebd3d8ef5a.tar.xz d9fcd4b7e2513ae5677ca44c3039a751e4bf1b927e9952b73eb96c1fc0ec3074 /usr/src/breakpad-cache .
git init src/third_party/lss
cd src/third_party/lss
git remote add origin https://chromium.googlesource.com/linux-syscall-support.git
git fetch --depth=1 origin 29164a80da4d41134950d76d55199ea33fbb9613
git reset --hard FETCH_HEAD
tevless-verify-source git linux-syscall-support https://chromium.googlesource.com/linux-syscall-support.git 29164a80da4d41134950d76d55199ea33fbb9613 29164a80da4d41134950d76d55199ea33fbb9613 none e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 linux-syscall-support-29164a80da4d.tar.xz dd834744c0d3a2c221e1dd3d4681bea2a9120444e742c07c9cc44440b6a56e6b /usr/src/breakpad-cache .
cd ../../..
CFLAGS="$CFLAGS -fno-lto" CXXFLAGS="$CXXFLAGS -fno-lto" ./configure
make -j$(nproc)
make DESTDIR=/usr/src/breakpad-cache install
cd ..
rm -rf breakpad
EOF

FROM builder AS webrtc
COPY --link --from=zlib /usr/src/zlib-cache /
COPY --link --from=mozjpeg /usr/src/mozjpeg-cache /
COPY --link --from=opus /usr/src/opus-cache /
COPY --link --from=openh264 /usr/src/openh264-cache /
COPY --link --from=dav1d /usr/src/dav1d-cache /
COPY --link --from=vpx /usr/src/vpx-cache /
COPY --link --from=ffmpeg /usr/src/ffmpeg-cache /
COPY --link --from=openssl /usr/src/openssl-cache /
COPY --link --from=xext /usr/src/xext-cache /
COPY --link --from=xfixes /usr/src/xfixes-cache /
COPY --link --from=xtst /usr/src/xtst-cache /
COPY --link --from=xrandr /usr/src/xrandr-cache /
COPY --link --from=xrender /usr/src/xrender-cache /
COPY --link --from=xdamage /usr/src/xdamage-cache /
COPY --link --from=xcomposite /usr/src/xcomposite-cache /
COPY --link --from=pipewire /usr/src/pipewire-cache /

# Shallow clone on a specific commit.
RUN --mount=type=cache,target=/var/cache/ccache <<EOF
git init tg_owt
cd tg_owt
git remote add origin https://github.com/desktop-app/tg_owt.git
git fetch --depth=1 origin 5c5c71258777d0196dbb3a09cc37d2f56ead28ab
git reset --hard FETCH_HEAD
git submodule update --init --recursive --depth=1
tevless-verify-source git tg-owt https://github.com/desktop-app/tg_owt.git 5c5c71258777d0196dbb3a09cc37d2f56ead28ab 5c5c71258777d0196dbb3a09cc37d2f56ead28ab recursive 6ffae21a62c86ecddc6707f02111fe6196c22c0c05ba792b9e959dbe6d9d5b7c tg-owt-5c5c71258777-recursive.tar.xz db038cfa4ecdcb3115aad513f2442fc85beb8496e7c58ef52ed6f05d95dfb3e6 /usr/src/webrtc-cache .
cmake -B build . -DTG_OWT_DLOPEN_PIPEWIRE=ON
cmake --build build
DESTDIR=/usr/src/webrtc-cache cmake --install build
cd ..
rm -rf tg_owt
EOF

FROM builder AS ada
RUN --mount=type=cache,target=/var/cache/ccache <<EOF
git clone -b v3.2.4 --depth=1 https://github.com/ada-url/ada.git
cd ada
tevless-verify-source git ada https://github.com/ada-url/ada.git v3.2.4 010f7c45aeaff1205452e7da2df8702cf725fb3e none e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 ada-v3.2.4.tar.xz 0875bb44ded41675672c95358753be64e92788ea050aa87c9fa92f81b0d34bd6 /usr/src/ada-cache .
cmake -B build . -DADA_TESTING=OFF -DADA_TOOLS=OFF -DADA_INCLUDE_URL_PATTERN=OFF
cmake --build build
DESTDIR=/usr/src/ada-cache cmake --install build
cd ..
rm -rf ada
EOF

FROM builder AS tde2e
COPY --link --from=zlib /usr/src/zlib-cache /
COPY --link --from=openssl /usr/src/openssl-cache /

# Shallow clone on a specific commit.
RUN --mount=type=cache,target=/var/cache/ccache <<EOF
git init tde2e
cd tde2e
git remote add origin https://github.com/tdlib/td.git
git fetch --depth=1 origin 51743dfd01dff6179e2d8f7095729caa4e2222e9
git reset --hard FETCH_HEAD
tevless-verify-source git tde2e https://github.com/tdlib/td.git 51743dfd01dff6179e2d8f7095729caa4e2222e9 51743dfd01dff6179e2d8f7095729caa4e2222e9 none e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 td-e2e-51743dfd01df.tar.xz 01b177a37fce1baec5b2571dc384d59127f4c1232213fa4d460a80da610904bb /usr/src/tde2e-cache .
cmake -B build . -DTD_E2E_ONLY=ON
cmake --build build
DESTDIR=/usr/src/tde2e-cache cmake --install build
cd ..
rm -rf tde2e
EOF

FROM builder
COPY --link --from=zlib /usr/src/zlib-cache /
COPY --link --from=xz /usr/src/xz-cache /
COPY --link --from=abseil /usr/src/abseil-cache /
COPY --link --from=protobuf /usr/src/protobuf-cache /
COPY --link --from=lcms2 /usr/src/lcms2-cache /
COPY --link --from=brotli /usr/src/brotli-cache /
COPY --link --from=highway /usr/src/highway-cache /
COPY --link --from=mozjpeg /usr/src/mozjpeg-cache /
COPY --link --from=opus /usr/src/opus-cache /
COPY --link --from=dav1d /usr/src/dav1d-cache /
COPY --link --from=openh264 /usr/src/openh264-cache /
COPY --link --from=de265 /usr/src/de265-cache /
COPY --link --from=vpx /usr/src/vpx-cache /
COPY --link --from=webp /usr/src/webp-cache /
COPY --link --from=avif /usr/src/avif-cache /
COPY --link --from=heif /usr/src/heif-cache /
COPY --link --from=jxl /usr/src/jxl-cache /
COPY --link --from=rnnoise /usr/src/rnnoise-cache /
COPY --link --from=xcb /usr/src/xcb-cache /
COPY --link --from=xcb-wm /usr/src/xcb-wm-cache /
COPY --link --from=xcb-util /usr/src/xcb-util-cache /
COPY --link --from=xcb-image /usr/src/xcb-image-cache /
COPY --link --from=xcb-keysyms /usr/src/xcb-keysyms-cache /
COPY --link --from=xcb-render-util /usr/src/xcb-render-util-cache /
COPY --link --from=xcb-cursor /usr/src/xcb-cursor-cache /
COPY --link --from=xext /usr/src/xext-cache /
COPY --link --from=xfixes /usr/src/xfixes-cache /
COPY --link --from=xv /usr/src/xv-cache /
COPY --link --from=xtst /usr/src/xtst-cache /
COPY --link --from=xrandr /usr/src/xrandr-cache /
COPY --link --from=xrender /usr/src/xrender-cache /
COPY --link --from=xdamage /usr/src/xdamage-cache /
COPY --link --from=xcomposite /usr/src/xcomposite-cache /
COPY --link --from=ffmpeg /usr/src/ffmpeg-cache /
COPY --link --from=openal /usr/src/openal-cache /
COPY --link --from=openssl /usr/src/openssl-cache /
COPY --link --from=xkbcommon /usr/src/xkbcommon-cache /
COPY --link --from=qt /usr/src/qt-cache /
COPY --link --from=boost /usr/src/boost-cache /
COPY --link --from=breakpad /usr/src/breakpad-cache /
COPY --link --from=webrtc /usr/src/webrtc-cache /
COPY --link --from=ada /usr/src/ada-cache /
COPY --link --from=tde2e /usr/src/tde2e-cache /

COPY --link --from=patches /usr/src/patches-cache/usr/local/share/tevless-build-provenance/patches.json /usr/local/share/tevless-build-provenance/patches.json
COPY --link --from=xcb-proto /usr/src/xcb-proto-cache/usr/local/share/tevless-build-provenance/xcbproto.json /usr/local/share/tevless-build-provenance/xcbproto.json
COPY --link --from=nv-codec-headers /usr/src/nv-codec-headers-cache/usr/local/share/tevless-build-provenance/nv-codec-headers.json /usr/local/share/tevless-build-provenance/nv-codec-headers.json
COPY --link --from=pipewire /usr/src/pipewire-cache/usr/local/share/tevless-build-provenance/pipewire.json /usr/local/share/tevless-build-provenance/pipewire.json

COPY --link --from=patches /usr/src/patches patches
RUN <<EOF
patch -p1 -d /usr/lib64/gobject-introspection -i $PWD/patches/gobject-introspection.patch
rm -rf patches
EOF

RUN <<'EOF'
python3 - <<'PY'
import json
import shutil
from pathlib import Path

source = Path("/usr/local/share/tevless-build-provenance")
files = sorted(source.glob("*.json"))
if len(files) != 49:
    raise SystemExit(
        "TeVLESS source provenance needs exactly 49 dependency rows; "
        f"found {len(files)}"
    )
expected_keys = {
    "archive",
    "archive_sha256",
    "checkout_head",
    "fetched_archive_sha256",
    "name",
    "origin",
    "resolved_revision",
    "revision",
    "source_kind",
    "submodules",
    "submodules_sha256",
}
records = []
for path in files:
    record = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(record, dict) or set(record) != expected_keys:
        raise SystemExit("invalid TeVLESS source provenance row: " + path.name)
    if path.name != record["name"] + ".json":
        raise SystemExit("misnamed TeVLESS source provenance row: " + path.name)
    if record["source_kind"] == "git":
        if (
            record["checkout_head"] != record["resolved_revision"]
            or record["fetched_archive_sha256"] is not None
        ):
            raise SystemExit("invalid Git source provenance row: " + path.name)
    elif record["source_kind"] == "upstream-archive":
        if (
            record["checkout_head"] is not None
            or record["fetched_archive_sha256"] != record["archive_sha256"]
        ):
            raise SystemExit("invalid archive source provenance row: " + path.name)
    else:
        raise SystemExit("invalid source kind in provenance row: " + path.name)
    records.append(record)
names = [record["name"] for record in records]
if len(names) != len(set(names)):
    raise SystemExit("duplicate TeVLESS source provenance rows")
records.sort(key=lambda record: record["name"])
target = Path("/usr/local/share/tevless/source-provenance.json")
target.parent.mkdir(parents=True, exist_ok=True)
target.write_text(
    json.dumps(
        {"dependencies": records, "schema": 1},
        sort_keys=True,
        separators=(",", ":"),
    )
    + "\n",
    encoding="utf-8",
)
target.chmod(0o444)
shutil.rmtree(source)
PY
EOF

ENV CCACHE_DISABLE=true
WORKDIR /usr/src/tdesktop
USER user
VOLUME [ "/usr/src/tdesktop" ]
CMD [ "/usr/src/tdesktop/Telegram/build/docker/centos_env/build.sh" ]
