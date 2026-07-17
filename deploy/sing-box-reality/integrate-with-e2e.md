# Stack REALITY with E2E Docker compose

From the server repo root:

```bash
cp deploy/sing-box-reality/config.json.example deploy/sing-box-reality/config.json
# Fill uuid / reality keys / short_id. Keep outbound server = "vocechat".

docker compose \
  -f build/docker/docker-compose.e2e.yml \
  -f build/docker/docker-compose.reality.yml \
  up -d --build
```

- Host `:443` → sing-box REALITY inbound.
- Overlay clears nginx host ports (`ports: !reset []`) so REALITY is the public entry.
- Clients use a local/remote sing-box REALITY outbound; after the tunnel, talk to VoceChat as usual HTTP(S).

See [README.md](README.md) and [SECURITY_E2E_AND_OBFUSCATION.md](../../docs/SECURITY_E2E_AND_OBFUSCATION.md).
