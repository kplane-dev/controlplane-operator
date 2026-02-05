FROM gcr.io/distroless/static:nonroot
ARG TARGETARCH
WORKDIR /
COPY ./.dev/bin/manager-linux-${TARGETARCH} /manager
USER 65532:65532

ENTRYPOINT ["/manager"]
