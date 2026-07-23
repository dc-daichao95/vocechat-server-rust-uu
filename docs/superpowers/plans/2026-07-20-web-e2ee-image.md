# Web E2EE Image Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `vocechat-server-web-e2ee:latest` from the existing toolchain-only `vocechat-server-base:latest` and provide, but do not start, the matching compose deployment.

**Architecture:** Use the base image independently for WASM, Web, and Rust build stages. Generate the missing E2EE WASM binary from the current Server core before building Web. Copy only verified artifacts into a Debian slim runtime image, with an atomic Web-seeding entrypoint. Keep nginx and runtime settings aligned with the existing root `compose.yml`.

**Tech Stack:** Docker BuildKit, Docker Compose v2, Rust 1.95, Node 22.23, pnpm 10.14, Debian Bookworm.

## Global Constraints

- Remote root: `/home/dcjjj/workspace/true_workspace/vocechat/gitwork`.
- Source repositories must remain unmodified, including existing uncommitted files.
- Final image must not contain Rust, Cargo, Node, pnpm, source trees, Git metadata, Android tooling, or signing secrets.
- Required Web outputs are `index.html`, `e2e-core/voce_e2ee_core_bg.wasm`, and `.e2e-image-version`.
- Do not run `docker compose up`.

---

### Task 1: Web-seeding runtime entrypoint

**Files:**
- Create: `/home/dcjjj/workspace/true_workspace/vocechat/gitwork/build/docker-entrypoint.web-e2ee.sh`
- Create: `/home/dcjjj/workspace/true_workspace/vocechat/gitwork/build/test-entrypoint.web-e2ee.sh`

**Interfaces:**
- Consumes: immutable Web seed at `/opt/vocechat/web-seed`.
- Produces: atomically updated `/home/vocechat-server/data/wwwroot`, then execs the server command.

- [ ] **Step 1: Copy the reviewed delivery entrypoint and test**

Run:

```bash
ROOT=/home/dcjjj/workspace/true_workspace/vocechat/gitwork
DELIVERY="$ROOT/vocechat-server-e2ee-delivery-20260717"
cp "$DELIVERY/docker-entrypoint.sh" "$ROOT/build/docker-entrypoint.web-e2ee.sh"
cp "$DELIVERY/test-entrypoint.sh" "$ROOT/build/test-entrypoint.web-e2ee.sh"
chmod +x "$ROOT/build/"*.web-e2ee.sh
```

Expected: both files exist and are executable.

- [ ] **Step 2: Run the entrypoint behavior test**

Run:

```bash
cd /home/dcjjj/workspace/true_workspace/vocechat/gitwork/build
ENTRYPOINT="$PWD/docker-entrypoint.web-e2ee.sh"
sed "s|ENTRYPOINT=\"\\$SCRIPT_DIR/docker-entrypoint.sh\"|ENTRYPOINT=\"$ENTRYPOINT\"|" \
  test-entrypoint.web-e2ee.sh > /tmp/test-entrypoint.web-e2ee.sh
sh /tmp/test-entrypoint.web-e2ee.sh
```

Expected: `PASS: docker-entrypoint E2E web seeding`.

### Task 2: Multi-stage Server/Web E2EE image

**Files:**
- Create: `/home/dcjjj/workspace/true_workspace/vocechat/gitwork/build/Dockerfile.web-e2ee`
- Create: `/home/dcjjj/workspace/true_workspace/vocechat/gitwork/build/Dockerfile.web-e2ee.dockerignore`

**Interfaces:**
- Consumes: `vocechat-server-base:latest`, `vocechat-web-uu`, `vocechat-server-rust-uu`, and Task 1 entrypoint.
- Produces: `vocechat-server-web-e2ee:latest`.

- [ ] **Step 1: Create the Dockerfile**

Write:

```dockerfile
FROM vocechat-server-base:latest AS wasm-builder
WORKDIR /src/server
COPY vocechat-server-rust-uu/ ./
RUN rustup target add wasm32-unknown-unknown \
 && cargo install wasm-bindgen-cli --version 0.2.118 --locked \
 && MLS_WASM_OUTPUT=/out/e2e-core \
      sh crates/voce-e2ee-core/scripts/build-wasm.sh \
 && test -s /out/e2e-core/voce_e2ee_core.js \
 && test -s /out/e2e-core/voce_e2ee_core_bg.wasm

FROM vocechat-server-base:latest AS web-builder
WORKDIR /src/web
COPY vocechat-web-uu/ ./
COPY --from=wasm-builder /out/e2e-core/ ./public/e2e-core/
RUN pnpm install --frozen-lockfile \
 && pnpm build:release \
 && test -s build/index.html \
 && test -s build/e2e-core/voce_e2ee_core_bg.wasm \
 && find build -type f ! -name .e2e-image-version -print0 \
      | sort -z \
      | xargs -0 sha256sum \
      | sha256sum \
      | cut -d ' ' -f 1 > build/.e2e-image-version \
 && test -s build/.e2e-image-version

FROM vocechat-server-base:latest AS server-builder
WORKDIR /src/server
COPY vocechat-server-rust-uu/ ./
RUN cargo build --locked --release \
 && test -x target/release/vocechat-server

FROM debian:bookworm-slim AS runtime
COPY --from=server-builder /etc/ssl/certs /etc/ssl/certs
COPY --from=server-builder /src/server/target/release/vocechat-server /home/vocechat-server/vocechat-server
COPY --from=server-builder /src/server/config /home/vocechat-server/config
COPY --from=web-builder /src/web/build/ /opt/vocechat/web-seed/
COPY build/docker-entrypoint.web-e2ee.sh /docker-entrypoint.sh
RUN sed -i '/^[[:space:]]*webclient_url[[:space:]]*=/d' /home/vocechat-server/config/config.toml \
 && chmod +x /docker-entrypoint.sh /home/vocechat-server/vocechat-server \
 && test -s /opt/vocechat/web-seed/index.html \
 && test -s /opt/vocechat/web-seed/e2e-core/voce_e2ee_core_bg.wasm \
 && test -s /opt/vocechat/web-seed/.e2e-image-version
ENV VOCECHAT_REQUIRE_WEB_SEED=1
EXPOSE 3000
WORKDIR /home/vocechat-server
ENTRYPOINT ["/docker-entrypoint.sh"]
```

- [ ] **Step 2: Build the image**

Create `build/Dockerfile.web-e2ee.dockerignore` before building:

```dockerignore
*
!vocechat-server-rust-uu/
!vocechat-server-rust-uu/**
!vocechat-web-uu/
!vocechat-web-uu/**
!build/
build/*
!build/docker-entrypoint.web-e2ee.sh
```

Run:

```bash
cd /home/dcjjj/workspace/true_workspace/vocechat/gitwork
sudo docker build \
  --progress=plain \
  -f build/Dockerfile.web-e2ee \
  -t vocechat-server-web-e2ee:latest \
  .
```

Expected: `naming to docker.io/library/vocechat-server-web-e2ee:latest`.

- [ ] **Step 3: Verify the image without starting the server**

Run:

```bash
sudo docker image inspect vocechat-server-web-e2ee:latest \
  --format '{{json .Config.Entrypoint}} {{.Config.WorkingDir}}'
sudo docker run --rm --entrypoint sh vocechat-server-web-e2ee:latest -c '
  test -x /home/vocechat-server/vocechat-server
  test -s /opt/vocechat/web-seed/index.html
  test -s /opt/vocechat/web-seed/e2e-core/voce_e2ee_core_bg.wasm
  ! command -v cargo
  ! command -v node
'
```

Expected: entrypoint `["/docker-entrypoint.sh"]`, working directory `/home/vocechat-server`, and exit code 0.

### Task 3: E2EE deployment compose

**Files:**
- Create: `/home/dcjjj/workspace/true_workspace/vocechat/gitwork/vocechat-server-e2ee-compose.yml`

**Interfaces:**
- Consumes: `vocechat-server-web-e2ee:latest` and existing nginx/cert/data paths.
- Produces: validated deployment configuration only; no containers are started.

- [ ] **Step 1: Create the compose file**

Write:

```yaml
services:
  vocechat:
    image: vocechat-server-web-e2ee:latest
    build:
      context: /home/dcjjj/workspace/true_workspace/vocechat/gitwork
      dockerfile: build/Dockerfile.web-e2ee
    container_name: vocechat-web-e2ee
    restart: always
    volumes:
      - "${VOCECHAT_DATA_DIR:-/home/dcjjj/workspace/true_workspace/vocechat/gitwork/data}:/home/vocechat-server/data"
    command:
      - --network.frontend_url
      - https://dcjjj888.duckdns.org:9443
    networks:
      - vocechat-e2ee-net

  nginx:
    image: nginx:alpine
    container_name: vocechat-nginx-web-e2ee
    restart: always
    depends_on:
      - vocechat
    ports:
      - "9443:443"
      - "9090:80"
    volumes:
      - /home/dcjjj/workspace/true_workspace/vocechat/gitwork/vocechat-nginx-conf/vocechat.conf:/etc/nginx/conf.d/default.conf:ro
      - "${VOCECHAT_SSL_DIR:-/home/dcjjj/workspace/true_workspace/vocechat/gitwork/vocechat-ssl}:/etc/nginx/certs:ro"
    networks:
      - vocechat-e2ee-net

networks:
  vocechat-e2ee-net:
    driver: bridge
```

- [ ] **Step 2: Validate without starting**

Run:

```bash
cd /home/dcjjj/workspace/true_workspace/vocechat/gitwork
sudo docker compose -f vocechat-server-e2ee-compose.yml config -q
sudo docker ps --format '{{.Names}}' | grep -E 'vocechat-web-e2ee|vocechat-nginx-web-e2ee' && exit 1 || true
```

Expected: config exits 0 and neither new container name exists.
