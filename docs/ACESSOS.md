# Catálogo de funções e acessos

Atualizado para 0.5.0. A instalação independente tem uma conta local **admin**,
com acesso integral. Todas as páginas exigem sessão válida, exceto login/static.
Todo POST exige CSRF. A senha inicial precisa ser trocada antes de administrar.
O core exige `X-Router-Token` em todas as APIs, exceto `/health`.

**Sistema / Configuração > Usuários e acessos** exibe o mesmo inventário funcional.
Não há concessões por pessoa/recurso nem manifest NanotechSoft nesta instalação.
Uma integração futura deverá usar login/sessão/catálogo central, substituindo
a conta local. Implementação e testes: [Administração e segurança](SEGURANCA_VLAN_ROTAS.md).

Recurso | Acesso
--- | ---
Interfaces/WAN/LAN, DHCP, dispositivos/apelidos, NAT/loopback, banda | admin integral
VLANs, rotas, firewall/regras/filtros/listas | admin integral
Sistema/alterar senha | admin com senha atual
Sistema/reiniciar | admin, senha atual e confirmação REINICIAR
Login | público, CSRF e limite de tentativas
Core | token interno; não acessível diretamente pela rede

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
| core | POST | `/api/nat/forward` | `nr_pf_save` (WAN e loopback LAN) |
| core | POST | `/api/nat/forward/delete` | `nr_pf_delete` (remove WAN e loopback LAN) |
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

| web | GET/POST | `/login` | Entrar |
| web | POST | `/logout` | Sair |
| web | GET | `/system` | Senha, estado/reinício, usuários e acessos |
| web | POST | `/system/password` | Trocar senha do painel |
| web | POST | `/system/reboot` | Confirmar e solicitar reinício |
| web | GET | `/vlans`, `/routes`, `/firewall` | Cadastro e estado |
| web | POST | `/manage/<section>/<operation>` | Validar seção/operação e encaminhar mutação autenticada |
| core | GET | `/api/system/info` | Estado e versão |
| core | POST | `/api/system/reboot` | Agendar reinício confirmado |
| core | POST | `/api/system/restore-links` | Recriar VLANs cadastradas no boot |
| core | GET | `/api/vlans`, `/api/routes`, `/api/firewall` | Cadastros, filtros, listas e estado |
| core | POST | `/api/vlans/save`, `/api/vlans/delete` | Criar/excluir VLAN, verificar dependências |
| core | POST | `/api/routes/save`, `/api/routes/delete` | Criar/editar/ativar/excluir rota |
| core | POST | `/api/firewall/save`, `/api/firewall/delete`, `/api/firewall/move` | CRUD e ordem de regras |
| core | POST | `/api/firewall/settings` | Ativar/desativar política e aplicar filtros |
| core | POST | `/api/firewall/lists` | Baixar categorias de fontes fixas |

As rotas genéricas aceitam somente as seções e operações listadas. O servidor
recusa token ausente/incorreto, entrada inválida, IDs desconhecidos e interfaces
em uso. Testes verificam login necessário, CSRF, senha inicial, expiração por
troca de senha, limitação de tentativas, páginas autenticadas e comandos rejeitados.

O menu compartilhado tem apresentação recolhível em celular, com indicação da
página atual, navegação por teclado e foco contido enquanto aberto. As tabelas
usam fichas em telas pequenas. Esta adaptação é visual: não cria recursos,
endpoints de negócio ou permissões; sessão, CSRF e token continuam valendo.
CSS/JavaScript de apresentação são servidos pela rota estática pública existente.
