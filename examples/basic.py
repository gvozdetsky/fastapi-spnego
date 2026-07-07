"""Minimal protected FastAPI app using fastapi-spnego.

Run (needs a service keytab and a Kerberos-enabled client browser/curl)::

    export SPNEGO_HOSTNAME=$(hostname -f)
    export SPNEGO_KEYTAB=/etc/myservice.keytab
    uvicorn examples.basic:app --host 0.0.0.0 --port 8000

Then, with a valid TGT (``kinit``)::

    curl --negotiate -u : http://$(hostname -f):8000/whoami
"""

from typing import Any

from fastapi import Depends, FastAPI

from fastapi_spnego import SpnegoAuth, SpnegoIdentity, ticket_lifetime

app = FastAPI(title="fastapi-spnego example")
spnego = SpnegoAuth()


@app.get("/whoami")
def whoami(identity: SpnegoIdentity = Depends(spnego)) -> dict[str, Any]:
    return {
        "principal": identity.principal,
        "username": identity.username,
        "realm": identity.realm,
        # Populated only when delegation is enabled and the client forwarded a TGT.
        "delegated_ccache": identity.delegated_ccache,
        "ticket_lifetime": identity.extra.get("ticket_lifetime"),
        # Remaining lifetime read back from the stored delegated ccache.
        "ccache_lifetime": ticket_lifetime(identity.delegated_ccache),
    }


@app.get("/health")
def health() -> dict[str, str]:
    # Unprotected — no SPNEGO dependency.
    return {"status": "ok"}
