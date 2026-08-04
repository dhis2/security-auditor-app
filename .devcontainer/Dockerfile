FROM ubuntu:24.04 AS devcontainer-ubuntu

ARG TZ
ENV TZ="$TZ"
ENV DEBIAN_FRONTEND=noninteractive

# Empty default - if not passed, we skip the mirror replacement
ARG UBUNTU_MIRROR=""

RUN if [ -n "$UBUNTU_MIRROR" ]; then \
    echo "Using custom Ubuntu mirror: $UBUNTU_MIRROR"; \
    MIRROR="${UBUNTU_MIRROR%/}"; \
    sed -i -E "s|^URIs:.*|URIs: ${MIRROR}|" \
    /etc/apt/sources.list.d/ubuntu.sources; \
    else \
    echo "Using default Ubuntu mirror"; \
    fi

# Define a non-root user for Visual Studio Code
ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=$USER_UID

# Check if this user exists
RUN apt-get update && apt-get install -y --no-install-recommends locales sudo \
    && EXISTING_USER=$(getent passwd "$USER_UID" | cut -d: -f1) \
    && if [ -n "$EXISTING_USER" ]; then \
    if [ "$EXISTING_USER" != "$USERNAME" ]; then \
    usermod  -l "$USERNAME" "$EXISTING_USER"; \
    usermod  -d "/home/$USERNAME" -m "$USERNAME"; \
    groupmod -n "$USERNAME" "$EXISTING_USER"; \
    fi; \
    usermod -s /usr/bin/bash "$USERNAME"; \
    else \
    groupadd --gid "$USER_GID" "$USERNAME"; \
    useradd --uid "$USER_UID" --gid "$USER_GID" -m -s /usr/bin/bash "$USERNAME"; \
    fi

# Allow passwordless sudo in the container
RUN echo "$USERNAME ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/user-$USERNAME-nopasswd \
    && chmod 0440 /etc/sudoers.d/user-$USERNAME-nopasswd

# Install useful packages
RUN apt-get install -y --no-install-recommends \
    age \
    aggregate \
    bash \
    bash-completion \
    bubblewrap \
    build-essential \
    ca-certificates \
    curl \
    diffutils \
    dnsutils \
    fd-find \
    file \
    fzf \
    gawk \
    gh \
    git \
    git-delta \
    gnupg2 \
    iproute2 \
    ipset \
    isort \
    jq \
    less \
    lsof \
    make \
    mc \
    man-db \
    openssh-client \
    procps \
    ripgrep \
    sed \
    shellcheck \
    socat \
    strace \
    tree \
    unzip \
    vim \
    wget \
    yamllint \
    yq \
    zip \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install opengrep (semgrep OSS fork). Pin version + SHA256 — the image build
# fails if the binary ever changes upstream. Single static binary, no runtime deps.
ARG OPENGREP_VERSION=1.25.0
ARG OPENGREP_SHA256=9ac4aebb47ba3f7b0d8fc641ac8749cb6c2f253f616131a67d9631e00d4bea33
RUN curl -fsSL "https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}/opengrep_manylinux_x86" -o /usr/local/bin/opengrep \
    && echo "${OPENGREP_SHA256}  /usr/local/bin/opengrep" | sha256sum -c - \
    && chmod +x /usr/local/bin/opengrep

ARG ASTGREP_VERSION=0.44.1
ARG ASTGREP_SHA256=611f9e5e76f2611ecea1a35dd3468ceedf600641a11224b80341d79c6ee7b9dd
RUN curl -fsSL "https://github.com/ast-grep/ast-grep/releases/download/${ASTGREP_VERSION}/app-x86_64-unknown-linux-gnu.zip" -o /tmp/ast.zip \
  && echo "${ASTGREP_SHA256}  /tmp/ast.zip" | sha256sum -c - \
  && unzip -p /tmp/ast.zip ast-grep > /usr/local/bin/ast-grep \
  && chmod +x /usr/local/bin/ast-grep \
  && rm /tmp/ast.zip

# Set environment variables to avoid noisy warnings
ENV DEVCONTAINER=true
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

# Fix shell for NVM installation and set paths
RUN ln -sf bash /usr/bin/sh
RUN echo 'export PATH="$HOME/.local/bin:$PATH"' | tee -a /home/$USERNAME/.bashrc

# Create workspace and config directories and set permissions
RUN mkdir -p /workspaces
RUN [ -n "$USERNAME" ] && mkdir -p "/home/$USERNAME"
RUN [ -n "$USERNAME" ] && chown -R $USERNAME:$USERNAME /workspaces "/home/$USERNAME"

WORKDIR /workspaces

# Set up non-root user
USER $USERNAME
