FROM ubuntu:16.04

LABEL maintainer="Yukai Zhao"

ENV DEBIAN_FRONTEND=noninteractive \
    FUZZ_HOME=/FuzzingTools \
    SUBJECT_HOME=/FuzzingSubjects \
    DOXYGEN_VERSION=1.9.1 \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    GOPATH=/go \
    PIN_ROOT=/pin-3.7-97619-g0d0c92f4f-gcc-linux

ARG INSTALL_LLVM15=1
ARG LLVM15_VERSION=15.0.7
ARG LLVM15_HOME=/clang+llvm-15.0.7
ARG CMAKE_BOOTSTRAP_VERSION=3.28.6
ARG HTTP_PROXY=""
ARG HTTPS_PROXY=""
ARG UBUNTU_MIRROR="http://mirrors.aliyun.com/ubuntu"
ENV http_proxy=${HTTP_PROXY} \
    https_proxy=${HTTPS_PROXY}

# Ubuntu 16.04 is EOL, probe multiple mirrors and pick the first usable one.
RUN set -eux; \
    printf '%s\n' 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99no-check-valid-until; \
    MIRRORS="${UBUNTU_MIRROR} http://mirrors.ustc.edu.cn/ubuntu http://mirrors.tuna.tsinghua.edu.cn/ubuntu http://mirrors.tencent.com/ubuntu http://archive.ubuntu.com/ubuntu http://old-releases.ubuntu.com/ubuntu"; \
    OK=0; \
    for m in ${MIRRORS}; do \
      printf '%s\n' \
        "deb ${m} xenial main restricted universe multiverse" \
        "deb ${m} xenial-updates main restricted universe multiverse" \
        "deb ${m} xenial-security main restricted universe multiverse" \
        "deb ${m} xenial-backports main restricted universe multiverse" \
        > /etc/apt/sources.list; \
      if apt-get update; then OK=1; break; fi; \
    done; \
    test "${OK}" = "1"

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        apt-transport-https \
        ca-certificates \
        software-properties-common \
        lsb-release \
        gnupg \
        curl \
        wget \
        git \
        vim \
        file \
        unzip \
        zip \
        xz-utils \
        liblzma-dev \
        build-essential \
        make \
        cmake \
        ninja-build \
        automake \
        autoconf \
        libtool \
        pkg-config \
        bison \
        flex \
        gcc \
        g++ \
        clang \
        llvm \
        llvm-dev \
        lcov \
        bear \
        graphviz \
        python \
        python-dev \
        python-pip \
        python-setuptools \
        python3 \
        python3-dev \
        python3-pip \
        python3-setuptools \
        zlib1g-dev \
        libglib2.0-dev \
        libpixman-1-dev \
        libsqlite3-dev \
        libssl-dev \
        libffi-dev \
        libblocksruntime-dev \
        binutils-dev \
        libbfd-dev \
        libunwind8-dev \
        libunwind-dev; \
    rm -rf /var/lib/apt/lists/*

# Optional predownloaded archives from host (place files under docker/preload).
COPY docker/preload /tmp/preload

RUN set -eux; \
    DOXYGEN_UNDERSCORE_VERSION="$(echo "${DOXYGEN_VERSION}" | tr '.' '_')"; \
    if [ -f "/tmp/preload/doxygen-${DOXYGEN_VERSION}.tar.gz" ]; then \
      cp /tmp/preload/doxygen-${DOXYGEN_VERSION}.tar.gz /tmp/doxygen.tar.gz; \
    else \
      (curl -fLk --retry 5 --retry-delay 3 -o /tmp/doxygen.tar.gz "https://github.com/doxygen/doxygen/archive/refs/tags/Release_${DOXYGEN_VERSION}.tar.gz" \
        || curl -fLk --retry 5 --retry-delay 3 -o /tmp/doxygen.tar.gz "https://github.com/doxygen/doxygen/archive/refs/tags/Release_${DOXYGEN_UNDERSCORE_VERSION}.tar.gz" \
        || curl -fLk --retry 5 --retry-delay 3 -o /tmp/doxygen.tar.gz "https://github.com/doxygen/doxygen/archive/refs/tags/v${DOXYGEN_VERSION}.tar.gz" \
        || curl -fLk --retry 5 --retry-delay 3 -o /tmp/doxygen.tar.gz "https://github.com/doxygen/doxygen/archive/refs/tags/${DOXYGEN_VERSION}.tar.gz" \
        || curl -fLk --retry 5 --retry-delay 3 -o /tmp/doxygen.tar.gz "https://codeload.github.com/doxygen/doxygen/tar.gz/refs/tags/Release_${DOXYGEN_VERSION}" \
        || curl -fLk --retry 5 --retry-delay 3 -o /tmp/doxygen.tar.gz "https://codeload.github.com/doxygen/doxygen/tar.gz/refs/tags/Release_${DOXYGEN_UNDERSCORE_VERSION}" \
        || curl -fLk --retry 5 --retry-delay 3 -o /tmp/doxygen.tar.gz "https://codeload.github.com/doxygen/doxygen/tar.gz/refs/tags/v${DOXYGEN_VERSION}" \
        || curl -fLk --retry 5 --retry-delay 3 -o /tmp/doxygen.tar.gz "https://codeload.github.com/doxygen/doxygen/tar.gz/refs/tags/${DOXYGEN_VERSION}"); \
    fi; \
    tar -xzf /tmp/doxygen.tar.gz -C /tmp; \
    DOXYGEN_SRC_DIR="$(find /tmp -maxdepth 1 -type d -name 'doxygen-*' | head -n 1)"; \
    test -n "${DOXYGEN_SRC_DIR}"; \
    cd "${DOXYGEN_SRC_DIR}"; \
    mkdir build; \
    cd build; \
    cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Release ..; \
    make -j"$(nproc)"; \
    make install; \
    doxygen --version | grep -x "${DOXYGEN_VERSION}"; \
    rm -rf /tmp/doxygen.tar.gz "${DOXYGEN_SRC_DIR}"

# LLVM 15 is used by the c-ares/FTS coverage-reproduction path. Ubuntu 16.04
# cannot reliably apt-install it, so prefer a preloaded toolchain and otherwise
# build the minimal clang/coverage/compiler-rt set from source.
RUN set -eux; \
    if [ "${INSTALL_LLVM15}" = "1" ]; then \
      LLVM_ARCHIVE=""; \
      for f in \
        "/tmp/preload/clang+llvm-${LLVM15_VERSION}-x86_64-linux-gnu-ubuntu-16.04.tar.xz" \
        "/tmp/preload/clang+llvm-${LLVM15_VERSION}-x86_64-linux-gnu.tar.xz" \
        "/tmp/preload/clang+llvm-${LLVM15_VERSION}.tar.xz"; do \
        if [ -f "${f}" ]; then LLVM_ARCHIVE="${f}"; break; fi; \
      done; \
      mkdir -p "${LLVM15_HOME}"; \
      if [ -n "${LLVM_ARCHIVE}" ]; then \
        tar -xJf "${LLVM_ARCHIVE}" -C "${LLVM15_HOME}" --strip-components=1; \
      else \
        CMAKE_BIN=cmake; \
        if ! cmake --version | awk 'NR==1 { split($3, v, "."); exit !((v[1] > 3) || (v[1] == 3 && v[2] >= 20)) }'; then \
          CMAKE_ARCHIVE="/tmp/preload/cmake-${CMAKE_BOOTSTRAP_VERSION}-linux-x86_64.tar.gz"; \
          if [ ! -f "${CMAKE_ARCHIVE}" ]; then \
            curl -fLk --retry 5 --retry-delay 3 -o "${CMAKE_ARCHIVE}" \
              "https://github.com/Kitware/CMake/releases/download/v${CMAKE_BOOTSTRAP_VERSION}/cmake-${CMAKE_BOOTSTRAP_VERSION}-linux-x86_64.tar.gz"; \
          fi; \
          mkdir -p /opt/cmake; \
          tar -xzf "${CMAKE_ARCHIVE}" -C /opt/cmake --strip-components=1; \
          CMAKE_BIN=/opt/cmake/bin/cmake; \
        fi; \
        LLVM_SRC_ARCHIVE="/tmp/preload/llvm-project-${LLVM15_VERSION}.src.tar.xz"; \
        if [ ! -f "${LLVM_SRC_ARCHIVE}" ]; then \
          curl -fLk --retry 5 --retry-delay 3 -o "${LLVM_SRC_ARCHIVE}" \
            "https://github.com/llvm/llvm-project/releases/download/llvmorg-${LLVM15_VERSION}/llvm-project-${LLVM15_VERSION}.src.tar.xz"; \
        fi; \
        rm -rf /tmp/llvm-project-${LLVM15_VERSION}.src /tmp/llvm15-build; \
        tar -xJf "${LLVM_SRC_ARCHIVE}" -C /tmp; \
        "${CMAKE_BIN}" -G Ninja \
          -S "/tmp/llvm-project-${LLVM15_VERSION}.src/llvm" \
          -B /tmp/llvm15-build \
          -DCMAKE_BUILD_TYPE=Release \
          -DCMAKE_INSTALL_PREFIX="${LLVM15_HOME}" \
          -DLLVM_ENABLE_PROJECTS="clang;compiler-rt" \
          -DLLVM_TARGETS_TO_BUILD=X86 \
          -DLLVM_INCLUDE_TESTS=OFF \
          -DLLVM_INCLUDE_EXAMPLES=OFF \
          -DLLVM_INCLUDE_BENCHMARKS=OFF \
          -DCOMPILER_RT_BUILD_LIBFUZZER=ON \
          -DCOMPILER_RT_BUILD_PROFILE=ON \
          -DCOMPILER_RT_BUILD_SANITIZERS=ON; \
        ninja -C /tmp/llvm15-build clang llvm-cov llvm-profdata llvm-symbolizer compiler-rt; \
        ninja -C /tmp/llvm15-build \
          install-clang install-clang-resource-headers install-llvm-cov \
          install-llvm-profdata install-llvm-symbolizer install-compiler-rt; \
        rm -rf /tmp/llvm-project-${LLVM15_VERSION}.src /tmp/llvm15-build; \
      fi; \
      ln -sfn "${LLVM15_HOME}" /clang+llvm-15; \
      ln -sfn "${LLVM15_HOME}" "/clang+llvm-${LLVM15_VERSION}"; \
      ln -sfn "${LLVM15_HOME}/bin/clang" /usr/local/bin/clang-15; \
      ln -sfn "${LLVM15_HOME}/bin/clang++" /usr/local/bin/clang++-15; \
      ln -sfn "${LLVM15_HOME}/bin/llvm-cov" /usr/local/bin/llvm-cov-15; \
      ln -sfn "${LLVM15_HOME}/bin/llvm-profdata" /usr/local/bin/llvm-profdata-15; \
      "${LLVM15_HOME}/bin/clang" --version | grep "15\\.0"; \
      "${LLVM15_HOME}/bin/llvm-cov" --version | grep "15\\.0"; \
      test -f "$("${LLVM15_HOME}/bin/clang" -print-resource-dir)/lib/linux/libclang_rt.profile-x86_64.a"; \
    fi; \
    rm -rf /tmp/preload

RUN set -eux; \
    python3 -m pip install --no-cache-dir \
        six \
        PyYAML \
        requests \
        cxxfilt \
        jinja2 || true; \
    python -m pip install --no-cache-dir \
        setuptools \
        psutil \
        pyyaml || true

WORKDIR ${FUZZ_HOME}
RUN mkdir -p ${SUBJECT_HOME} ${FUZZ_HOME}/Legion

COPY docker/AFL ${FUZZ_HOME}/AFL
COPY docker/aflfast ${FUZZ_HOME}/aflfast
COPY docker/afl-rb ${FUZZ_HOME}/afl-rb
COPY docker/AFLplusplus ${FUZZ_HOME}/AFLplusplus
COPY docker/honggfuzz ${FUZZ_HOME}/honggfuzz
COPY docker/radamsa ${FUZZ_HOME}/radamsa
COPY docker/Angora ${FUZZ_HOME}/Angora
COPY docker/preload ${FUZZ_HOME}/preload
COPY docker/update-alternatives-clang.sh docker/legion.sh docker/libstdc++.so.6* ${FUZZ_HOME}/
COPY src ${FUZZ_HOME}/Legion/src
COPY scripts ${FUZZ_HOME}/Legion/scripts
COPY doxygen.config README.md ${FUZZ_HOME}/Legion/

# Build local fuzzers shipped in this repository.
RUN set -eux; \
    make -C AFL clean all; \
    make -C aflfast clean all; \
    make -C afl-rb clean all; \
    make -C honggfuzz clean all; \
    make -C radamsa clean everything

# Build AFL++ from local source tree.
RUN set -eux; \
    make -C AFLplusplus clean all

# Build Angora (Ubuntu 16.04 compatible path from upstream project).
RUN set -eux; \
    cd Angora; \
    sed -i 's/\r$//' ./build/*.sh; \
    chmod +x ./build/*.sh; \
    export PATH="/usr/local/cargo/bin:${PATH}"; \
    (bash ./build/install_rust.sh \
      && PREFIX=/ bash ./build/install_llvm.sh \
      && bash ./build/install_tools.sh \
      && bash ./build/build.sh \
      && bash ./build/install_pin_mode.sh) || true

# Install QSYM. If upstream build fails, install a compatibility wrapper so QSYM.sh can still run.
RUN set -eux; \
    if git clone --depth 1 https://github.com/sslab-gatech/qsym.git /tmp/QSYM-src; then \
      cp -r /tmp/QSYM-src ${FUZZ_HOME}/QSYM; \
      cd ${FUZZ_HOME}/QSYM; \
      git submodule update --init --recursive || true; \
      python -m pip install --no-cache-dir virtualenv; \
      if [ -f ./setup.py ]; then python ./setup.py install || true; fi; \
      if [ -f ./build.py ]; then python ./build.py --afl=${FUZZ_HOME}/AFLplusplus || true; fi; \
      rm -rf /tmp/QSYM-src; \
    else \
      mkdir -p ${FUZZ_HOME}/QSYM/bin; \
      printf '%s\n' \
        '#!/usr/bin/env python3' \
        'import argparse' \
        'import subprocess' \
        '' \
        'p = argparse.ArgumentParser(add_help=False)' \
        "p.add_argument('-a', default='afl-slave')" \
        "p.add_argument('-o', required=True)" \
        "p.add_argument('-n', required=True)" \
        "p.add_argument('-i')" \
        "p.add_argument('--')" \
        'args, rest = p.parse_known_args()' \
        '' \
        "if '--' in rest:" \
        "    idx = rest.index('--')" \
        '    target = rest[idx + 1:]' \
        'else:' \
        '    target = rest' \
        '' \
        "mode = ['-M', args.n] if args.a == 'afl-master' else ['-S', args.n]" \
        "cmd = ['afl-fuzz', '-i', args.i or 'input', '-o', args.o] + mode + ['--'] + target" \
        'raise SystemExit(subprocess.call(cmd))' \
        > ${FUZZ_HOME}/QSYM/bin/run_qsym_afl.py; \
      chmod +x ${FUZZ_HOME}/QSYM/bin/run_qsym_afl.py; \
    fi

# Build the public Legion source copied into this image.
RUN set -eux; \
    make -C ${FUZZ_HOME}/Legion/src/instrumentor; \
    make -C ${FUZZ_HOME}/Legion/src/legion; \
    mkdir -p ${FUZZ_HOME}/Legion/bin; \
    cp ${FUZZ_HOME}/Legion/src/legion/legion ${FUZZ_HOME}/Legion/bin/legion

# Compatibility with legacy hardcoded paths used by Legion scripts.
RUN set -eux; \
    mkdir -p /home/threedean; \
    ln -sfn ${FUZZ_HOME} /home/threedean/FuzzingTools; \
    ln -sfn ${FUZZ_HOME}/aflfast ${FUZZ_HOME}/AFLFast; \
    ln -sfn ${FUZZ_HOME}/afl-rb ${FUZZ_HOME}/FairFuzz

# Ensure all Legion scripts are executable.
RUN set -eux; \
    chmod +x ${FUZZ_HOME}/Legion/scripts/*.sh; \
    chmod +x ${FUZZ_HOME}/update-alternatives-clang.sh; \
    chmod +x ${FUZZ_HOME}/legion.sh; \
    cp ${FUZZ_HOME}/legion.sh ${SUBJECT_HOME}; \
    cp ${FUZZ_HOME}/libstdc++.so.6* /usr/lib/x86_64-linux-gnu/ || true

ENV LEGION_SCRIPT_DIR="${FUZZ_HOME}/Legion/scripts" \
    LEGION_PATH="${FUZZ_HOME}/Legion" \
    TOOLS_ROOT="${FUZZ_HOME}" \
    PATH="${FUZZ_HOME}/radamsa/bin:${FUZZ_HOME}/honggfuzz/hfuzz_cc:${FUZZ_HOME}/honggfuzz:${FUZZ_HOME}/AFLplusplus:${FUZZ_HOME}/Legion/bin:${FUZZ_HOME}/Legion/scripts:${PATH}" \
    LD_LIBRARY_PATH="${FUZZ_HOME}/Angora/clang+llvm/lib:${LD_LIBRARY_PATH}"

WORKDIR ${SUBJECT_HOME}
CMD ["/bin/bash"]
