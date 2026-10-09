# syntax=docker/dockerfile:1
#
# The aos CLI (standard library only). Build and run with:
#   docker build -t agent-off-switch .
#   docker run --rm -v "$PWD/exports:/work/exports:ro" agent-off-switch review exports
# The container reads the mounted folder and writes only to standard output or the --out path you give.
#
# The base image is pinned by digest (python:3.12-slim, multi-arch index).
ARG PYTHON_IMAGE=python:3.12-slim@sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016

# Build the wheel in a throwaway stage so the build backend never reaches the runtime image.
FROM ${PYTHON_IMAGE} AS build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
WORKDIR /src
COPY pyproject.toml README.md LICENSE CHANGELOG.md ./
COPY src/ src/
RUN pip wheel --no-deps --wheel-dir /wheels .

FROM ${PYTHON_IMAGE}
ARG VERSION=0.0.0-dev
LABEL org.opencontainers.image.title="agent-off-switch" \
      org.opencontainers.image.description="Find every AI agent identity in Microsoft 365, AWS and GitHub, see what it can reach, and switch it off" \
      org.opencontainers.image.source="https://github.com/basitalisandhu/agent-off-switch" \
      org.opencontainers.image.url="https://github.com/basitalisandhu/agent-off-switch" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1 PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/home/app
RUN --mount=type=bind,from=build,source=/wheels,target=/wheels \
    pip install /wheels/*.whl \
 && useradd --uid 1000 --user-group --create-home --home-dir /home/app --shell /usr/sbin/nologin app
# Mount the export folder under /work.
WORKDIR /work
USER 1000:1000
ENTRYPOINT ["aos"]
CMD ["--help"]
