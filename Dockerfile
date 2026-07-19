FROM rust:1-bookworm

ARG USERNAME=rustdev
ARG USER_UID=1000
ARG USER_GID=1000

RUN apt-get update \
    && apt-get install --no-install-recommends --yes \
        build-essential \
        ca-certificates \
        pkg-config \
        libssl-dev \
        git \
        curl \
        sudo \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid "${USER_GID}" "${USERNAME}" \
    && useradd --uid "${USER_UID}" --gid "${USER_GID}" --create-home --shell /bin/bash "${USERNAME}" \
    && usermod --append --groups sudo "${USERNAME}" \
    && printf '%s ALL=(root) NOPASSWD:ALL\n' "${USERNAME}" > "/etc/sudoers.d/${USERNAME}" \
    && chmod 0440 "/etc/sudoers.d/${USERNAME}" \
    && mkdir -p /workspace /usr/local/cargo \
    && chown -R "${USER_UID}:${USER_GID}" /workspace /usr/local/cargo

RUN rustup component add rustfmt clippy

ENV CARGO_HOME=/usr/local/cargo
WORKDIR /workspace
USER ${USERNAME}

CMD ["bash"]
