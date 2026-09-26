from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    send_file
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
            headers={"X-Router-Token": os.environ.get("ROUTER_API_TOKEN", "")},
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
            headers={"X-Router-Token": os.environ.get("ROUTER_API_TOKEN", "")},
            timeout=120
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


from security import install as install_security
current_admin = install_security(app)


@app.get("/system")
def system_page():
    return render_template("system.html", data=get("/api/system/info"), initial=current_admin()["initial"])


@app.post("/system/reboot")
def system_reboot():
    from werkzeug.security import check_password_hash
    if not check_password_hash(current_admin()["password"], request.form.get("password", "")):
        flash("Senha incorreta; reinício cancelado.")
    elif request.form.get("confirmation") != "REINICIAR":
        flash("Digite REINICIAR para confirmar.")
    else:
        result = post("/api/system/reboot", {"confirmation": "REINICIAR"})
        flash(result.get("message", "Falha ao solicitar reinício."))
    return redirect(url_for("system_page"))


@app.get("/vlans")
@app.get("/routes")
@app.get("/firewall")
def management_page():
    section = request.path.strip("/")
    data = get("/api/" + section)
    if not data.get("success"):
        flash(data.get("message", "Não foi possível carregar as configurações."))
    selected = next((r for r in data.get("items", []) if r.get("id") == request.args.get("edit")), {})
    return render_template(section + ".html", data=data, selected=selected,
                           interfaces=get("/api/interfaces").get("interfaces", []))


@app.post("/manage/<section>/<operation>")
def management_save(section, operation):
    if section not in ("vlans", "routes", "firewall") or operation not in ("save", "delete", "move", "settings", "lists"):
        from flask import abort
        abort(404)
    data = request.form.to_dict()
    return_tab = data.pop("_tab", "")
    for field in ("enabled", "vpn_ports", "remote_ports", "dns_enabled", "block_encrypted_dns",
                  "block_ipv6", "block_page_enabled", "block_page_https"):
        data[field] = request.form.get(field) == "on"
    data["categories"] = request.form.getlist("categories")
    data["interfaces"] = request.form.getlist("interfaces")
    result = post("/api/" + section + "/" + operation, data)
    flash(result.get("message", "Configuração salva." if result.get("success") else "Falha ao salvar."))
    tab = ""
    if section == "firewall" and operation in ("lists", "settings"):
        tab = "?tab=" + ("lists" if operation == "lists" else
                          "blockpage" if return_tab == "blockpage" else "profiles")
    return redirect("/" + section + tab)


@app.post("/firewall/block-ca/prepare")
def block_ca_prepare():
    result = post("/api/firewall/blockpage/prepare", {})
    flash(result.get("message", "Falha preparando certificado."))
    return redirect("/firewall?tab=blockpage")


@app.get("/firewall/block-ca")
def block_ca_download():
    path = "/data/blockpage/ca.crt"
    if not os.path.isfile(path):
        flash("Prepare o certificado antes do download.")
        return redirect("/firewall?tab=blockpage")
    return send_file(path, mimetype="application/x-x509-ca-cert", as_attachment=True,
                     download_name="nanotechrouter-block-page-ca.crt", conditional=True)


@app.get("/loadbalance")
def loadbalance_page():
    data = get("/api/loadbalance")
    selected = next((item for item in data.get("members", [])
                     if item.get("id") == request.args.get("edit")), {})
    return render_template("loadbalance.html", data=data, selected=selected)


@app.post("/loadbalance/settings")
def loadbalance_settings():
    result = post("/api/loadbalance/settings", {
        "enabled": request.form.get("enabled") == "on",
        "mode": request.form.get("mode", "balance"),
        "health_target": request.form.get("health_target", "1.1.1.1")
    })
    flash(result.get("message", "Configuração salva."))
    return redirect(url_for("loadbalance_page"))


@app.post("/loadbalance/member")
def loadbalance_member():
    result = post("/api/loadbalance/member", {
        "id": request.form.get("id", ""), "name": request.form.get("name", ""),
        "interface": request.form.get("interface", ""), "gateway": request.form.get("gateway", ""),
        "weight": request.form.get("weight", "1"), "priority": request.form.get("priority", "10"),
        "enabled": request.form.get("enabled") == "on"
    })
    flash(result.get("message", "Link salvo."))
    return redirect(url_for("loadbalance_page"))


@app.post("/loadbalance/member/delete")
def loadbalance_member_delete():
    result = post("/api/loadbalance/member/delete", {"id": request.form.get("id", "")})
    flash(result.get("message", "Link removido."))
    return redirect(url_for("loadbalance_page"))


@app.post("/loadbalance/check")
def loadbalance_check():
    result = post("/api/loadbalance/check", {})
    flash("Verificação concluída." if result.get("success") else result.get("message", "Falha na verificação."))
    return redirect(url_for("loadbalance_page"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
