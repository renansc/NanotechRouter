# Catálogo de funções e acessos

Inventário das rotas existentes na versão atualizada em 25/09/2026.
A interface web não implementa autenticação/autorização por usuário. O core
escuta exclusivamente em 127.0.0.1:5050 e recebe as chamadas da interface web.
O acesso administrativo depende das restrições de rede do ambiente.
ROUTER_SECRET_KEY assina cookies; não cria autenticação nem altera permissões.

Esta aplicação independente não possui manifest app.json nem Config > Usuarios
e acessos. Nenhuma concessão de acesso foi adicionada na preparação para Git.
Não é possível testar perfis de usuário autorizados/não autorizados enquanto
não existir esse mecanismo. As validações de entrada das rotas permanecem.
A eventual integração ao NanotechSoft deverá reutilizar o login único e incluir
os recursos nos manifests, nas verificações de servidor e no catálogo central.

Reservas DHCP adicionam consulta, cadastro/edição e exclusão no mesmo limite de
acesso administrativo existente. NAT reutiliza a rota de cadastro para edição,
com validação do ID e dos conflitos no servidor. Nenhum novo perfil ou concessão
foi criado. A aplicação não possui manifest nem cadastro de usuários integrados.
Os testes verificam rejeição de entradas inválidas e de IDs inexistentes; perfis
individuais permanecem não aplicáveis enquanto não existir autenticação.

| Componente | Método | Rota | Função |
| --- | --- | --- | --- |
| web | GET | `/` | `dashboard` |
| web | GET | `/interfaces` | `interfaces` |
| web | POST | `/wan/set` | `wan_set` |
| web | POST | `/lan/set` | `lan_set` |
| web | POST | `/lan/delete` | `lan_delete` |
| web | GET | `/dhcp` | `dhcp` |
| web | POST | `/dhcp/reservation` | `dhcp_reservation_save` |
| web | POST | `/dhcp/reservation/delete` | `dhcp_reservation_delete` |
| web | GET | `/ports` | `ports` |
| web | POST | `/ports/alias` | `port_alias` |
| web | GET | `/devices` | `devices` |
| web | POST | `/devices/discover` | `devices_discover` |
| web | POST | `/devices/name` | `device_name` |
| web | GET | `/nat` | `nat_page` |
| web | POST | `/nat/forward` | `nat_forward_save` |
| web | POST | `/nat/forward/delete` | `nat_forward_delete` |
| web | GET | `/bandwidth` | `bandwidth_page` |
| web | POST | `/bandwidth/rule` | `bandwidth_save` |
| web | POST | `/bandwidth/delete` | `bandwidth_delete` |
| core | GET | `/api/ports/aliases` | `api_port_aliases` |
| core | POST | `/api/ports/alias` | `api_port_alias` |
| core | GET | `/api/devices` | `api_devices` |
| core | POST | `/api/devices/discover` | `api_devices_discover` |
| core | POST | `/api/devices/name` | `api_device_name` |
| core | GET | `/api/dhcp/reservations` | `dhcp_reservations` |
| core | POST | `/api/dhcp/reservation` | `dhcp_reservation_save` |
| core | POST | `/api/dhcp/reservation/delete` | `dhcp_reservation_delete` |
| core | GET | `/api/nat/status` | `nr_nat_status` |
| core | GET | `/api/nat/forwards` | `nr_pf_list` |
| core | POST | `/api/nat/forward` | `nr_pf_save` |
| core | POST | `/api/nat/forward/delete` | `nr_pf_delete` |
| core | GET | `/api/bandwidth` | `nr_bw_list` |
| core | POST | `/api/bandwidth/rule` | `nr_bw_save` |
| core | POST | `/api/bandwidth/delete` | `nr_bw_delete` |
| core | POST | `/api/system/reapply` | `nr_reapply` |
| core | GET | `/health` | `health` |
| core | GET | `/api/status` | `status` |
| core | GET | `/api/interfaces` | `interfaces` |
| core | POST | `/api/wan/set` | `set_wan` |
| core | POST | `/api/lan/set` | `set_lan` |
| core | POST | `/api/lan/delete` | `delete_lan` |
| core | GET | `/api/dhcp/leases` | `leases` |
| core | GET | `/api/config` | `config` |
