# Claude Bridge — Setup

## 1. Compilar en cada VPS

```bash
git clone <tu-repo>/claude-bridge
cd claude-bridge
cargo build --release
cp target/release/bridge-server /usr/local/bin/
cp target/release/bridge-mcp /usr/local/bin/
```

## 2. Correr el servidor en UNO de los VPS (o un servidor central)

```bash
# En VPS-1 (la que tiene IP pública accesible)
PORT=3001 bridge-server
```

Para correrlo como servicio:
```bash
cat > /etc/systemd/system/claude-bridge.service << EOF
[Unit]
Description=Claude Bridge Server
After=network.target

[Service]
ExecStart=/usr/local/bin/bridge-server
Environment=PORT=3001
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl enable claude-bridge
systemctl start claude-bridge
```

## 3. Configurar Claude Code en cada VPS

**VPS-1 (instancia SaaS)** — `~/.claude/settings.json`:
```json
{
  "mcpServers": {
    "bridge": {
      "command": "bridge-mcp",
      "args": [
        "--server", "http://localhost:3001",
        "--channel", "pentest",
        "--name", "saas"
      ]
    }
  }
}
```

**VPS-2 (instancia pentesting)** — `~/.claude/settings.json`:
```json
{
  "mcpServers": {
    "bridge": {
      "command": "bridge-mcp",
      "args": [
        "--server", "http://IP-DE-VPS-1:3001",
        "--channel", "pentest",
        "--name", "pentester"
      ]
    }
  }
}
```

## 4. Uso en Claude Code

**Desde la instancia SaaS** — compartir un endpoint para testear:
```
share_endpoint(
  url: "https://api.tuapp.com/api/users/login",
  method: "POST",
  headers: {"Authorization": "Bearer eyJ..."},
  body: '{"email":"test@test.com","password":"123"}',
  notes: "endpoint de login, valida JWT, no tiene rate limit"
)
```

**Desde la instancia pentesting** — leer el endpoint y reportar:
```
read_messages(channel: "pentest")
# ve el endpoint compartido, lo testea, luego:
report_finding(
  title: "SQL Injection en /api/users/login",
  severity: "critical",
  endpoint: "POST /api/users/login",
  detail: "El parámetro email no está sanitizado. Payload: ' OR 1=1--"
)
```

**Mensajes simples en tiempo real:**
```
send_message(content: "oye, el token expira en 15 min, apúrate")
read_messages()
```

## Canales recomendados

- `pentest` — endpoints para testear y findings
- `general` — coordinación general
- `saas` — contexto del código del SaaS
