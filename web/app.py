from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash
)

import os
import requests

app = Flask(__name__)

app.secret_key = os.environ["ROUTER_SECRET_KEY"]
if not app.secret_key:
    raise RuntimeError("Configure ROUTER_SECRET_KEY antes de iniciar a aplicação.")

CORE = "http://127.0.0.1:5050"


def get(path):

    try:

        r = requests.get(
            CORE + path,
            timeout=10
        )

        return r.json()

    except Exception as e:

        return {
            "success": False,
            "message": str(e)
        }


def post(path, data):

    try:

        r = requests.post(
            CORE + path,
            json=data,
            timeout=20
        )

        return r.json()

    except Exception as e:

        return {
            "success": False,
            "message": str(e)
        }


@app.route("/")
def dashboard():

    data = get(
        "/api/interfaces"
    )

    leases = get(
        "/api/dhcp/leases"
    )

    return render_template(
        "dashboard.html",
        data=data,
        leases=leases
    )


@app.route("/interfaces")
def interfaces():

    data = get(
        "/api/interfaces"
    )

    return render_template(
        "interfaces.html",
        data=data
    )


@app.route(
    "/wan/set",
    methods=["POST"]
)
def wan_set():

    result = post(
        "/api/wan/set",
        {
            "interface":
                request.form["interface"]
        }
    )

    flash(
        result.get(
            "message",
            "Operação concluída."
        )
    )

    return redirect(
        url_for("interfaces")
    )


@app.route(
    "/lan/set",
    methods=["POST"]
)
def lan_set():

    result = post(
        "/api/lan/set",
        {
            "interface":
                request.form["interface"],

            "address":
                request.form["address"],

            "dhcp":
                request.form.get(
                    "dhcp"
                ) == "on",

            "dhcp_start":
                request.form.get(
                    "dhcp_start",
                    ""
                ),

            "dhcp_end":
                request.form.get(
                    "dhcp_end",
                    ""
                ),

            "dns":
                request.form.get(
                    "dns",
                    "1.1.1.1"
                ),

            "internet":
                request.form.get(
                    "internet"
                ) == "on"
        }
    )

    flash(
        result.get(
            "message",
            "Operação concluída."
        )
    )

    return redirect(
        url_for("interfaces")
    )


@app.route(
    "/lan/delete",
    methods=["POST"]
)
def lan_delete():

    result = post(
        "/api/lan/delete",
        {
            "interface":
                request.form["interface"]
        }
    )

    flash(
        result.get(
            "message",
            "Operação concluída."
        )
    )

    return redirect(
        url_for("interfaces")
    )


@app.route("/dhcp")
def dhcp():

    leases = get(
        "/api/dhcp/leases"
    )

    data = get(
        "/api/interfaces"
    )

    reservations = get("/api/dhcp/reservations")
    selected = next((r for r in reservations.get("reservations", [])
                     if r.get("id") == request.args.get("edit")), None)
    if selected is None:
        selected = {key: request.args.get(key, "") for key in ("interface", "mac", "ip", "hostname")}

    return render_template(
        "dhcp.html",
        leases=leases,
        data=data,
        reservations=reservations,
        selected=selected
    )


@app.route("/dhcp/reservation", methods=["POST"])
def dhcp_reservation_save():
    result = post("/api/dhcp/reservation", {key: request.form.get(key, "")
                  for key in ("id", "interface", "mac", "ip", "hostname")})
    flash(result.get("message", "Operação concluída."))
    return redirect(url_for("dhcp"))


@app.route("/dhcp/reservation/delete", methods=["POST"])
def dhcp_reservation_delete():
    result = post("/api/dhcp/reservation/delete", {"id": request.form.get("id", "")})
    flash(result.get("message", "Operação concluída."))
    return redirect(url_for("dhcp"))


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000
    )


# ============================================================
# PORTAS
# ============================================================

@app.route("/ports")
def ports():

    data = get(
        "/api/interfaces"
    )

    aliases = get(
        "/api/ports/aliases"
    )

    return render_template(
        "ports.html",
        data=data,
        aliases=aliases
    )


@app.route(
    "/ports/alias",
    methods=["POST"]
)
def port_alias():

    result = post(
        "/api/ports/alias",
        {
            "interface":
                request.form[
                    "interface"
                ],

            "alias":
                request.form.get(
                    "alias",
                    ""
                )
        }
    )

    flash(
        result.get(
            "message",
            "Operação concluída."
        )
    )

    return redirect(
        url_for("ports")
    )


# ============================================================
# DISPOSITIVOS
# ============================================================

@app.route("/devices")
def devices():

    devices_data = get(
        "/api/devices"
    )

    return render_template(
        "devices.html",
        data=devices_data
    )


@app.route(
    "/devices/discover",
    methods=["POST"]
)
def devices_discover():

    result = post(
        "/api/devices/discover",
        {}
    )

    if result.get(
        "success"
    ):

        flash(
            "Descoberta da rede concluída."
        )

    else:

        flash(
            result.get(
                "message",
                "Falha na descoberta."
            )
        )

    return redirect(
        url_for("devices")
    )


@app.route(
    "/devices/name",
    methods=["POST"]
)
def device_name():

    result = post(
        "/api/devices/name",
        {
            "mac":
                request.form[
                    "mac"
                ],

            "name":
                request.form.get(
                    "name",
                    ""
                )
        }
    )

    flash(
        result.get(
            "message",
            "Operação concluída."
        )
    )

    return redirect(
        url_for("devices")
    )

# NANOTECHROUTER_WEB_V040_BEGIN

@app.route("/nat")
def nat_page():
    forwards = get("/api/nat/forwards")
    selected = next((r for r in forwards.get("rules", [])
                     if str(r.get("id")) == request.args.get("edit")), {})
    return render_template(
        "nat.html",
        nat=get("/api/nat/status"),
        forwards=forwards,
        selected=selected,
        aliases=get("/api/ports/aliases")
    )

@app.route("/nat/forward", methods=["POST"])
def nat_forward_save():
    result = post("/api/nat/forward", {
        "id": request.form.get("id", ""),
        "name": request.form.get("name", ""),
        "protocol": request.form.get("protocol", "tcp"),
        "external_port": request.form.get("external_port", ""),
        "internal_ip": request.form.get("internal_ip", ""),
        "internal_port": request.form.get("internal_port", ""),
        "enabled": request.form.get("enabled") == "on"
    })
    flash(result.get("message", "Operação concluída."))
    return redirect(url_for("nat_page"))

@app.route("/nat/forward/delete", methods=["POST"])
def nat_forward_delete():
    result = post("/api/nat/forward/delete", {"id": request.form["id"]})
    flash(result.get("message", "Operação concluída."))
    return redirect(url_for("nat_page"))

@app.route("/bandwidth")
def bandwidth_page():
    return render_template(
        "bandwidth.html",
        rules=get("/api/bandwidth"),
        devices=get("/api/devices"),
        aliases=get("/api/ports/aliases")
    )

@app.route("/bandwidth/rule", methods=["POST"])
def bandwidth_save():
    try:
        down = int(request.form.get("download_mbps", "0") or 0)
        up = int(request.form.get("upload_mbps", "0") or 0)
        if down < 0 or up < 0:
            raise ValueError()
    except ValueError:
        flash("Informe limites inteiros maiores ou iguais a zero.")
        return redirect(url_for("bandwidth_page"))

    result = post("/api/bandwidth/rule", {
        "ip": request.form["ip"],
        "interface": request.form["interface"],
        "download_mbps": down,
        "upload_mbps": up,
        "enabled": down > 0 or up > 0
    })
    flash(result.get("message", "Operação concluída."))
    return redirect(url_for("bandwidth_page"))

@app.route("/bandwidth/delete", methods=["POST"])
def bandwidth_delete():
    result = post("/api/bandwidth/delete", {"ip": request.form["ip"]})
    flash(result.get("message", "Operação concluída."))
    return redirect(url_for("bandwidth_page"))

# NANOTECHROUTER_WEB_V040_END
