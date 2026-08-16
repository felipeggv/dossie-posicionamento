#!/usr/bin/env python3
"""
rebuild.py — decifra, edita e recifra o dossiê (index.html).

O repositório guarda APENAS o artefato cifrado. Este script é a única
forma sancionada de mexer no conteúdo sem redescobrir o esquema cripto
a cada sessão.

Esquema (fixo, não alterar sem atualizar o gate em index.html):
    PBKDF2-SHA256, 600.000 iterações → AES-256-GCM

Uso:
    # extrai o conteúdo em claro para um arquivo
    python3 tools/rebuild.py extract index.html <senha> > /tmp/claro.html

    # recifra um conteúdo editado de volta no index.html
    python3 tools/rebuild.py pack index.html /tmp/claro.html <senha>

    # confere que o index.html abre e contém uma string
    python3 tools/rebuild.py verify index.html <senha> "texto esperado"

SEGURANÇA — por que `pack` sorteia salt e IV novos a cada execução:
    AES-GCM quebra catastroficamente se o par (chave, IV) for reutilizado
    com conteúdo diferente. A chave deriva da senha + salt; como a senha
    não muda, reaproveitar o IV antigo com um payload novo vazaria o XOR
    dos dois textos em claro. Salt e IV novos a cada build eliminam isso.

A senha NUNCA é gravada em disco nem commitada. Ela entra por argumento.
"""

import base64
import hashlib
import os
import re
import sys

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    sys.exit("falta a lib: pip3 install cryptography")

ITER = 600_000
DECL = re.compile(
    r'const SALT="(?P<salt>[^"]+)",\s*IV="(?P<iv>[^"]+)",\s*DADOS="(?P<dados>[^"]+)",\s*ITER=(?P<iter>\d+);'
)


def _params(shell_html):
    m = DECL.search(shell_html)
    if not m:
        sys.exit("não achei a declaração const SALT=..,IV=..,DADOS=..,ITER=..; no index.html")
    return m


def _key(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITER, 32)


def extract(shell_path, password):
    shell = open(shell_path, encoding="utf-8").read()
    m = _params(shell)
    if int(m.group("iter")) != ITER:
        sys.exit(f"ITER no arquivo ({m.group('iter')}) difere do esperado ({ITER})")
    salt = base64.b64decode(m.group("salt"))
    iv = base64.b64decode(m.group("iv"))
    data = base64.b64decode(m.group("dados"))
    return AESGCM(_key(password, salt)).decrypt(iv, data, None).decode("utf-8")


def pack(shell_path, plain_path, password):
    shell = open(shell_path, encoding="utf-8").read()
    plain = open(plain_path, encoding="utf-8").read()
    m = _params(shell)

    salt = os.urandom(16)  # novo a cada build — ver nota de segurança no topo
    iv = os.urandom(12)
    cipher = AESGCM(_key(password, salt)).encrypt(iv, plain.encode("utf-8"), None)

    decl = (
        f'const SALT="{base64.b64encode(salt).decode()}", '
        f'IV="{base64.b64encode(iv).decode()}", '
        f'DADOS="{base64.b64encode(cipher).decode()}", '
        f"ITER={ITER};"
    )
    out = shell[: m.start()] + decl + shell[m.end():]
    open(shell_path, "w", encoding="utf-8").write(out)

    # round-trip obrigatório: um build que não reabre é um build quebrado
    back = extract(shell_path, password)
    if back != plain:
        sys.exit("FALHA: o round-trip não bateu — index.html NÃO confiável")
    print(f"ok  payload={len(plain)} chars  index.html={len(out)} chars  round-trip confere")


def verify(shell_path, password, needle):
    plain = extract(shell_path, password)
    hit = needle in plain
    print(f'{"ok" if hit else "FALHA"}  "{needle[:60]}" {"encontrado" if hit else "AUSENTE"}')
    sys.exit(0 if hit else 1)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    cmd = sys.argv[1]
    if cmd == "extract":
        sys.stdout.write(extract(sys.argv[2], sys.argv[3]))
    elif cmd == "pack":
        pack(sys.argv[2], sys.argv[3], sys.argv[4])
    elif cmd == "verify":
        verify(sys.argv[2], sys.argv[3], sys.argv[4])
    else:
        sys.exit(__doc__)
