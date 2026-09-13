#!/bin/bash

set -e

INSTALL_DIR="/etc/speednet/checkuser"
APP_FILE="$INSTALL_DIR/app.py"
SERVICE_FILE="/etc/systemd/system/checkuser-api.service"
MENU_FILE="/usr/local/bin/checkuser"
PORT="8000"

if [ "$EUID" -ne 0 ]; then
    echo "Ejecuta este instalador como root."
    exit 1
fi

echo "========================================"
echo "      INSTALADOR CHECKUSER"
echo "========================================"

echo "[1/6] Instalando dependencias..."
apt update
apt install -y python3 python3-pip curl

python3 -m pip install flask --break-system-packages 2>/dev/null || \
python3 -m pip install flask

echo "[2/6] Creando carpeta..."
mkdir -p "$INSTALL_DIR"

echo "[3/6] Creando app.py..."

cat > "$APP_FILE" <<'PY'
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, jsonify, Response, request
import subprocess
import datetime
import json
import time
import threading
import os
import signal
import re
from collections import defaultdict

app = Flask(__name__)


class SSHLimiterOptimized:

    def __init__(self, cache_duration=30):
        self.cache_duration = cache_duration
        self.cache_usuarios_limites = {}
        self.cache_timestamp = 0

    def obter_usuarios_limites(self):
        tempo_atual = time.time()

        if tempo_atual - self.cache_timestamp < self.cache_duration:
            return self.cache_usuarios_limites

        usuarios_limites = {}

        try:
            import pwd

            for usuario in pwd.getpwall():
                gecos = usuario.pw_gecos.strip()

                if not gecos:
                    continue

                partes = gecos.split(",", 1)

                try:
                    limite = int(partes[0])
                except ValueError:
                    continue

                if limite > 0:
                    usuarios_limites[usuario.pw_name] = limite

        except Exception as e:
            print(f"Erro ao ler limites de /etc/passwd: {e}")

        self.cache_usuarios_limites = usuarios_limites
        self.cache_timestamp = tempo_atual
        return usuarios_limites

    def _ler_cmdline_processo(self, pid):
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                return (
                    f.read()
                    .replace(b"\x00", b" ")
                    .decode("utf-8", errors="replace")
                    .strip()
                )
        except:
            return ""

    def _uid_real_processo(self, pid):
        try:
            with open(f"/proc/{pid}/status", "r") as f:
                for linha in f:
                    if linha.startswith("Uid:"):
                        return int(linha.split()[1])
        except:
            pass

        return None

    def _uid_do_usuario(self, usuario):
        try:
            import pwd
            return pwd.getpwnam(usuario).pw_uid
        except:
            return None

    def obter_conexoes_ssh_rapido(self):
        conexoes = defaultdict(int)

        try:
            for entrada in os.scandir("/proc"):
                if not entrada.name.isdigit():
                    continue

                pid = int(entrada.name)
                cmdline = self._ler_cmdline_processo(pid)

                if not cmdline.startswith("sshd: "):
                    continue

                if "[priv]" in cmdline:
                    continue

                match = re.match(r"^sshd:\s+([^\s@]+)", cmdline)

                if not match:
                    continue

                usuario = match.group(1)

                uid_real = self._uid_real_processo(pid)
                uid_usuario = self._uid_do_usuario(usuario)

                if uid_real is None or uid_usuario is None:
                    continue

                if uid_real != uid_usuario:
                    continue

                conexoes[usuario] += 1

        except Exception as e:
            print(f"Erro ao obter conexões: {e}")

        return dict(conexoes)


limiter = SSHLimiterOptimized()


def _obter_expiration_date(username):
    try:
        resultado = subprocess.run(
            ["chage", "-l", username],
            capture_output=True,
            text=True,
            timeout=5,
            env={**os.environ, "LC_ALL": "C"}
        )

        for linha in resultado.stdout.splitlines():
            if linha.startswith("Account expires"):
                data = linha.split(":", 1)[1].strip()

                if data.lower() == "never":
                    return None

                return data

    except:
        pass

    return None


def _calcular_dias_restantes(expiration_date):
    if not expiration_date:
        return None

    try:
        date_obj = datetime.datetime.strptime(
            expiration_date.strip(),
            "%b %d, %Y"
        ).date()

        return max(
            0,
            (date_obj - datetime.date.today()).days
        )

    except:
        return None


def _obter_tempo_conectado(username):
    try:
        resultado = subprocess.run(
            f"ps -u {username} -o etime --sort=etime | tail -n 1",
            shell=True,
            capture_output=True,
            text=True,
            timeout=5
        )

        tempo = resultado.stdout.strip()

        return tempo if tempo and tempo != "ELAPSED" else None

    except:
        return None


@app.route("/check", methods=["GET"])
def listar_usuarios():
    usuarios = []

    try:
        with open("/etc/passwd", "r") as f:
            for linha in f:
                dados = linha.strip().split(":")
                usuarios.append({
                    "username": dados[0]
                })

    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500

    return jsonify(usuarios)


@app.route("/check/<username>", methods=["GET"])
def buscar_usuario(username):
    try:
        conexoes_por_usuario = limiter.obter_conexoes_ssh_rapido()
        usuarios_limites = limiter.obter_usuarios_limites()

        count_connections = conexoes_por_usuario.get(username, 0)
        limit_connections = usuarios_limites.get(username)

        expiration_date = _obter_expiration_date(username)

        dados_usuario = {
            "username": username,
            "count_connections": count_connections,
            "limit_connections": limit_connections,
            "expiration_date": expiration_date,
            "expiration_days": (
                _calcular_dias_restantes(expiration_date)
                if expiration_date else None
            ),
            "time_online": _obter_tempo_conectado(username)
        }

        return Response(
            json.dumps(dados_usuario),
            mimetype="application/json"
        )

    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500


@app.route("/checkUser", methods=["POST"])
def verificar_usuario():
    try:
        data = request.get_json()

        if not data or "user" not in data:
            return jsonify({
                "error": "Dados de usuário ausentes"
            }), 400

        username = data["user"]

        conexoes = limiter.obter_conexoes_ssh_rapido()
        limites = limiter.obter_usuarios_limites()

        expiration_date = _obter_expiration_date(username)

        return jsonify({
            "username": username,
            "count_connection": conexoes.get(username, 0),
            "limiter_user": limites.get(username),
            "expiration_date": expiration_date,
            "expiration_days": _calcular_dias_restantes(expiration_date),
            "time_online": _obter_tempo_conectado(username)
        })

    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500


@app.route("/", methods=["GET"])
def inicio():
    return jsonify({
        "status": "online",
        "service": "CheckUser"
    })


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=8000,
        debug=False,
        use_reloader=False
    )
PY

chmod +x "$APP_FILE"

echo "[4/6] Creando servicio..."

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=CheckUser API
After=network.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $APP_FILE
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

echo "[5/6] Creando menu..."

cat > "$MENU_FILE" <<'SH'
#!/bin/bash

SERVICE="checkuser-api"
APP="/etc/speednet/checkuser/app.py"
PORT="8000"

pausa() {
    echo
    read -rp "Presiona ENTER para continuar..."
}

while true; do
    clear

    echo "========================================"
    echo "          CHECKUSER MANAGER"
    echo "========================================"
    echo "[1] Ver estado"
    echo "[2] Reiniciar servicio"
    echo "[3] Iniciar servicio"
    echo "[4] Detener servicio"
    echo "[5] Ver logs"
    echo "[6] Probar usuario"
    echo "[7] Probar API"
    echo "[8] Mostrar URL DTunnel"
    echo "[9] Editar app.py"
    echo "[0] Salir"
    echo "========================================"

    read -rp "Opcion: " opcion

    case "$opcion" in
        1)
            systemctl status "$SERVICE" --no-pager
            pausa
            ;;
        2)
            systemctl restart "$SERVICE"
            echo "Servicio reiniciado."
            pausa
            ;;
        3)
            systemctl start "$SERVICE"
            echo "Servicio iniciado."
            pausa
            ;;
        4)
            systemctl stop "$SERVICE"
            echo "Servicio detenido."
            pausa
            ;;
        5)
            journalctl -u "$SERVICE" -n 60 --no-pager
            pausa
            ;;
        6)
            read -rp "Usuario SSH: " usuario
            echo
            curl -s "http://127.0.0.1:${PORT}/check/${usuario}?deviceId=prueba"
            echo
            pausa
            ;;
        7)
            curl -s "http://127.0.0.1:${PORT}/check"
            echo
            pausa
            ;;
        8)
            IP=$(curl -4 -s --max-time 3 https://api.ipify.org)

            echo
            echo "URL DTunnel:"
            echo "http://${IP}:${PORT}"
            echo
            pausa
            ;;
        9)
            nano "$APP"
            ;;
        0)
            exit 0
            ;;
        *)
            echo "Opcion invalida."
            sleep 1
            ;;
    esac
done
SH

chmod +x "$MENU_FILE"

echo "[6/6] Activando servicio..."

python3 -m py_compile "$APP_FILE"

systemctl daemon-reload
systemctl enable checkuser-api
systemctl restart checkuser-api

sleep 2

echo
echo "========================================"
echo " INSTALACION COMPLETADA"
echo "========================================"
echo
systemctl status checkuser-api --no-pager || true
echo
echo "Para abrir el menu:"
echo
echo "  checkuser"
echo
echo "Puerto:"
echo
echo "  $PORT"
echo
