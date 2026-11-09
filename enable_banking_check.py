"""Local, read-only connection check for Enable Banking and Jæren Sparebank."""
import base64
from datetime import datetime, timedelta, timezone
from getpass import getpass
import json
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from uuid import UUID
import webbrowser

API_HOST = "api.enablebanking.com"
CALLBACK = "https://localhost:8080/callback"
KEY_DIRECTORY = Path.home() / ".config" / "enable-banking"


class CheckError(Exception):
    pass


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def b64url(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=")


def signed_token(key, app_id):
    now = int(datetime.now(timezone.utc).timestamp())
    header = {"typ": "JWT", "alg": "RS256", "kid": app_id}
    claims = {"iss": "enablebanking.com", "aud": API_HOST, "iat": now, "exp": now + 300}
    message = b".".join(b64url(json.dumps(part).encode()) for part in (header, claims))
    signature = subprocess.run(
        ["/usr/bin/openssl", "dgst", "-sha256", "-sign", str(key)],
        input=message,
        capture_output=True,
        check=False,
    )
    if signature.returncode:
        raise CheckError("Kunne ikke signere med PEM-nøkkelen.")
    return (message + b"." + b64url(signature.stdout)).decode("ascii")


def api_request(path, token, payload=None):
    request = Request(
        f"https://{API_HOST}{path}",
        data=None if payload is None else json.dumps(payload).encode(),
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
    )
    try:
        with build_opener(NoRedirects()).open(request, timeout=30) as response:
            return json.load(response)
    except HTTPError as error:
        with error:
            try:
                code = json.load(error).get("code", "")
            except (ValueError, AttributeError):
                code = ""
        detail = f" ({code})" if isinstance(code, str) and re.fullmatch(r"[A-Z_]{3,64}", code) else ""
        raise CheckError(f"Enable Banking svarte HTTP {error.code}{detail}.") from None
    except (URLError, TimeoutError):
        raise CheckError("Kunne ikke nå Enable Banking API. Kjør skriptet i vanlig Terminal på Macen.") from None


def read_callback(address, state):
    received = urlsplit(address.strip())
    expected = urlsplit(CALLBACK)
    if received._replace(query="") != expected:
        raise CheckError("Returadressen samsvarer ikke med den registrerte localhost-adressen.")
    params = parse_qs(received.query)
    if params.get("state") != [state]:
        raise CheckError("Returadressen tilhører ikke denne innloggingen.")
    if "error" in params or len(params.get("code", [])) != 1:
        raise CheckError("Banken returnerte ingen godkjent autorisasjonskode.")
    return params["code"][0]


def choose_account(accounts):
    if not accounts:
        raise CheckError("Ingen kontoer ble returnert. Sjekk at kontoen er koblet og godkjent.")
    if len(accounts) == 1:
        return accounts[0]
    suffix = getpass("Siste fire siffer på kontoen du vil teste: ").strip()
    if not re.fullmatch(r"[0-9]{4}", suffix):
        raise CheckError("Oppgi nøyaktig fire siffer.")
    matches = [
        account
        for account in accounts
        if ((account.get("account_id") or {}).get("iban") or "").endswith(suffix)
    ]
    if len(matches) != 1:
        raise CheckError("Fant ikke én entydig konto med de fire sifrene. Velg én konto i samtykket.")
    return matches[0]


def main():
    if not sys.stdin.isatty():
        raise CheckError("Kjør skriptet interaktivt i Terminal på Macen.")
    keys = sorted(KEY_DIRECTORY.glob("*.pem"))
    if len(keys) != 1 or not keys[0].is_file():
        raise CheckError("Legg én Enable Banking-nøkkel i ~/.config/enable-banking/.")
    key = keys[0]
    if key.stat().st_mode & 0o077:
        raise CheckError("Begrens PEM-filen til din bruker med chmod 600 før du kjører testen.")
    try:
        app_id = str(UUID(key.stem))
    except ValueError:
        raise CheckError("PEM-filen må ha Application ID som filnavn, etterfulgt av .pem.") from None

    def call(path, payload=None):
        return api_request(path, signed_token(key, app_id), payload)

    banks = call("/aspsps?country=NO&psu_type=personal&service=AIS")["aspsps"]
    bank = next((item for item in banks if item["name"].casefold() == "jæren sparebank"), None)
    if bank is None:
        raise CheckError("Fant ikke Jæren Sparebank i API-ets liste for privat kontoinformasjon.")

    # The browser retains the localhost URL for manual copy. Avoid sending it to an existing listener.
    try:
        connection = socket.create_connection(("localhost", 8080), timeout=0.5)
    except OSError:
        pass
    else:
        connection.close()
        raise CheckError("Port 8080 er allerede i bruk. Stopp den lokale tjenesten før testen.")

    state = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    authorization = call("/auth", {
        "access": {"valid_until": (now + timedelta(hours=1)).isoformat(timespec="seconds")},
        "aspsp": {"name": bank["name"], "country": "NO"},
        "state": state,
        "redirect_url": CALLBACK,
        "psu_type": "personal",
    })
    auth_url = authorization["url"]
    destination = urlsplit(auth_url)
    hostname = destination.hostname or ""
    if destination.scheme != "https" or not (
        hostname == "enablebanking.com" or hostname.endswith(".enablebanking.com")
    ) or destination.username is not None:
        raise CheckError("API-et returnerte en uventet innloggingsadresse.")

    print("Godkjenn kontodeling i nettleseren. Når den går tilbake til localhost,")
    print("kopier hele adressen fra adressefeltet, selv om siden ikke åpner seg.")
    if not webbrowser.open(auth_url):
        print("Åpne denne innloggingslenken i nettleseren:", auth_url)
    code = read_callback(getpass("Lim returadressen inn her i Terminal: "), state)
    session = call("/sessions", {"code": code})
    account_id = str(UUID(choose_account(session["accounts"])["uid"]))
    account_path = f"/accounts/{account_id}"
    balances = call(f"{account_path}/balances")["balances"]
    print("Saldo kunne leses." if balances else "API-et returnerte ingen saldo.")

    date_from = (now.date() - timedelta(days=6)).isoformat()
    query = urlencode({"date_from": date_from})
    page = call(f"{account_path}/transactions?{query}")
    count = len(page["transactions"])
    if page.get("continuation_key"):
        print(f"Transaksjoner på første side siden {date_from}: {count}. Det finnes flere sider.")
    else:
        print(f"Transaksjoner siden {date_from}: {count}.")


if __name__ == "__main__":
    try:
        main()
    except CheckError as error:
        sys.exit(str(error))
    except (ValueError, KeyError, TypeError):
        sys.exit("Fikk et uventet svar. Ingen rådata ble skrevet ut.")
    except (KeyboardInterrupt, EOFError):
        sys.exit("Avbrutt.")
