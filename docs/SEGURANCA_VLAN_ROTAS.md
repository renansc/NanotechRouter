# Administração, VLANs, rotas e firewall (0.5.0)

## Login e Sistema / Configuração

Esta instalação é independente do NanotechSoft. Por solicitação do operador,
possui administrador local `admin` com senha inicial `admin`. O primeiro acesso
exige escolher senha de 10 a 128 caracteres antes de administrar a rede. Não
há cadastro de outros usuários nesta versão. A senha inicial só é criada se
não existe cadastro; atualizar/reiniciar nunca redefine a senha existente.

A senha fica em hash scrypt em `data/auth/admin.sqlite3`, com permissão 0600.
Login limita cinco tentativas incorretas por IP em 15 minutos. Sessões duram
até oito horas; mudar a senha invalida as demais. Todos os POST exigem CSRF.
Cookies usam HttpOnly e SameSite Strict. O painel atual continua HTTP na porta
5000; o tráfego de login não é criptografado. Usar a rede de gestão ou Tailscale;
HTTPS com certificado não faz parte desta mudança. Não publicar o painel na
Internet. A troca de senha afeta somente o painel, não o usuário SSH do Linux.

**Sistema / Configuração > Usuários e acessos** apresenta a conta e o catálogo
administrativo. O perfil admin tem acesso integral aos recursos listados em
[ACESSOS.md](ACESSOS.md); não há permissões individuais por recurso ainda.

O core continua em loopback e exige `X-Router-Token` igual ao segredo local
`ROUTER_API_TOKEN`, gerado separadamente da chave de sessão. Apenas `/health`
é público. O Compose passa o token ao painel; o core e a restauração no boot
leem a mesma variável do `.env` protegido. Não enviar `.env` ao Git.

Em **Estado e reinício**, o botão exige a senha atual e a palavra `REINICIAR`.
O servidor agenda `systemctl reboot` para cinco segundos depois. Abrir a tela,
salvar outras configurações, implantar código ou rodar testes não reinicia o
roteador. O estado mostra versão, nome do host, uptime e encaminhamento IPv4.

## VLANs

Em **VLANs**, escolher uma porta física, ID 1–4094 e nome. A criação usa uma
subinterface 802.1Q `porta.ID` sem trocar a configuração da porta física.
O switch/AP conectado precisa suportar 802.1Q e ter o mesmo ID permitido no
trunk. A tela não configura switches ou pontos de acesso externos.

Depois, em **Interfaces / WAN / LAN**, configurar endereço, DHCP e acesso à
Internet da nova interface. O servidor impede sobreposição de faixas com outras
interfaces. Em **Firewall**, cadastrar as permissões de tráfego entre redes.
VLAN não é por si só uma proibição de roteamento entre sub-redes.

A exclusão exige retirar previamente o uso em LAN/WAN, rotas e perfis do
firewall. Alterar uma identificação física significa remover seu uso e criar
outra VLAN; não há renumeração automática de redes ativas. Cadastros ficam em
`data/vlans.json`. A restauração de boot cria/verifica as VLANs antes de aplicar
endereços LAN e DHCP. Não altera VLANs criadas por outros programas.

## Rotas estáticas IPv4

**Rotas** permite criar, editar, ativar/desativar e excluir destino CIDR, gateway,
interface e métrica. Gateway deve ser outro host diretamente conectado à
interface. A tela recusa rota padrão, sobreposição com redes conectadas,
métrica inválida e duplicação destino/métrica. IPv6 não é suportado no cadastro.

Rotas ficam em `data/routes.json` e na tabela main com protocolo 243.
O código usa add/del com os atributos completos e nunca replace/flush de rotas
alheias. Se uma edição falhar, tenta restaurar a rota anterior e relata falhas
de restauração. Políticas de VPN podem ter precedência sobre rotas main; o
cadastro não substitui políticas ou rotas da Tailscale.

## Firewall e isolamento

A instalação mantém o firewall novo **desativado**, sem inventar regras para
as redes do operador. Em **Firewall > Regras entre redes**, configurar IPv4
ou CIDR de origem/destino, protocolo, porta ou intervalo e ação. As regras
podem ser editadas, desabilitadas, excluídas e reordenadas pelas setas.

A primeira regra correspondente decide. Regras Permitir devem vir antes dos
bloqueios gerais. Sem correspondência, esta tabela permite o encaminhamento;
outras políticas do sistema continuam valendo. Ativar em **Ativação e filtros**.
Uma regra Permitir também encerra a avaliação dos perfis de portas desta tabela.
As exceções de DNS são configuradas separadamente.

Exemplo com endereços de documentação:

1. Permitir origem `192.0.2.0/24`, destino `198.51.100.10`, TCP 443.
2. Bloquear origem `192.0.2.0/24`, destino `198.51.100.0/24`, todos os protocolos.
3. Se necessário, bloquear também conexões iniciadas no sentido contrário,
   invertendo as redes em outra regra abaixo das exceções pertinentes.

O retorno da conexão segue a regra de sua direção original usando conntrack.
O destino/porta são os do serviço interno após DNAT, quando há NAT. Bloqueios
IPv4 de encaminhamento alcançam também conexões já rastreadas; não existe uma
liberação de ESTABLISHED antes das regras. Não é necessário limpar globalmente
conntrack. A avaliação não controla tráfego entre hosts que conversam no mesmo
segmento sem atravessar o roteador: para isso, usar VLANs ou isolamento no switch/AP.

Regras de encaminhamento não bloqueiam acesso ao próprio painel/gateway (INPUT)
e não alteram o tráfego originado pelo roteador (OUTPUT). A gestão deve continuar
restrita à rede administrativa. Não há editor genérico de INPUT/OUTPUT nesta versão.

A tabela dedicada `inet nanotechrouter_policy`, hook forward prioridade -20,
é validada com nft --check e substituída numa transação. Nenhum flush ruleset.
Regras de NAT, Docker, Tailscale e QoS são preservadas. O encaminhamento entre
LANs cadastradas recebe passagem na DOCKER-USER para funcionar também quando
Docker define FORWARD DROP; os bloqueios nft anteriores continuam prevalecendo.
Falhas ao aplicar tentam restaurar política/DNS anteriores e não gravam a nova
configuração. Regras/contadores atuais aparecem em **Regras aplicadas**; os
contadores zeram ao reaplicar. Arquivo persistente: `data/firewall.json`.

## Filtros de serviços e DNS

Selecionar LANs e, opcionalmente, um IPv4/CIDR de origem dos perfis. Os perfis
não mudam o escopo das regras manuais da primeira aba.

- VPN: UDP 500/4500/1194/1701/51820, TCP 1194/1723 e ESP/AH/GRE.
- Acesso remoto: TCP 22/23/3389/5900–5999/5938/6568/21115–21119;
  UDP 3389/5938/21116.
- DNS criptografado: TCP 853; UDP 853/784/8853 (quando filtro DNS está ativo).
- IPv6: opção separada bloqueia todo encaminhamento IPv6, nas duas direções,
  das LANs selecionadas. Não depende do campo origem IPv4. Sem ela, as regras
  IPv4 não protegem tráfego IPv6.

O filtro DNS usa uma instância separada de dnsmasq na porta 1053, escutando
loopback e os gateways selecionados; INPUT impede acesso ao resolver por outras
interfaces. NAT redireciona TCP/UDP 53 dessas LANs/origens para a instância.
DNS/DHCP existentes, leases, opções DHCP e endereços dos clientes são preservados.
O filtro usa upstreams 1.1.1.1 e 9.9.9.9; exceções de domínio usam 1.1.1.1.
A exceção por IP pula o redirecionamento DNS, não as regras manuais ou de portas.

Domínios personalizados incluem subdomínios. Informar `example.com`, sem esquema,
caminho ou porta; URLs completas são recusadas para não prometer inspeção do
caminho HTTPS. Uma exceção mais específica pode liberar subdomínio de uma zona
bloqueada. Bloqueios mais específicos que uma exceção ampla ainda prevalecem
pela seleção de sufixo mais específico do dnsmasq. O uso de `local=/dominio/`
bloqueia todos os tipos de registro, incluindo HTTPS/SVCB.

Redes sociais e acesso remoto têm uma lista inicial explícita de domínios
conhecidos, ampliável por domínios personalizados. Não são classificadores
universais de sites. Conteúdo adulto e VPN/proxy/DNS criptografado usam listas
HaGeZi baixadas em **Listas de categorias**, com contagem e data do download.
O download usa URLs HTTPS fixas, limite 32 MB e valida todos os domínios antes
de gravar em `data/category_*.json`. Lista vazia/errada preserva a anterior.
Não existe fetch de URL arbitrária nem atualização agendada oculta.

Baixar listas não ativa filtros: depois do download, salvar **Ativação e filtros**
para aplicar a versão nova. As listas baixadas não entram no Git. Falhas de rede
não removem as versões armazenadas. A interface exige uma base disponível antes
de ativar conteúdo adulto ou VPN por DNS.

Limites: portas/domínios não são DPI/NGFW, não identificam todos os túneis VPN,
DoH/acesso remoto sobre HTTPS 443, IPs fixos ou novas categorias. Cache DNS e
conexões existentes podem exigir renovação/reinício do aplicativo. Gestão de
dispositivos, inspeção de aplicações e controle de DNS criptografado são medidas
adicionais necessárias para políticas resistentes à evasão. Não há proxy TLS,
IDS/IPS ou filtragem de caminhos HTTPS nesta versão.

## Persistência e validação

O utilitário existente `deploy/nanotechrouter-safe-restore` autentica chamadas ao
core e restaura VLANs, LAN/DHCP, regras locais de roteamento, NAT/QoS, rotas
estáticas e firewall/DNS. Não restaura banco nem importa backups. A configuração
Gunicorn mantém um worker no core e timeout 120 s para downloads/validação.

Testes unitários usam dados sintéticos e comandos simulados. Testes nativos
recusam a rede principal e devem ser executados explicitamente:

```sh
sudo unshare --net core/venv/bin/python tests/check_management_native.py
sudo unshare --net core/venv/bin/python tests/check_firewall_native.py
```

O primeiro cria namespaces temporários e testa TCP real (exceção IP/porta,
ordenação, ida/volta, bloqueio inverso, desativação), VLAN/rotas reais e DNS
interceptado com upstream sintético. Testa domínios/subdomínios/HTTPS-SVCB,
exceção de domínio e de IP sem usar clientes da rede real. O segundo valida
NAT com nft/iptables reais. Nenhum teste reinicia o equipamento.

Referências primárias: [nftables — chains e vereditos](https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains),
[dnsmasq — manual](https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html),
[HaGeZi — listas e licenças](https://github.com/hagezi/dns-blocklists).

Validação desta entrega: 38 testes unitários passaram, além dos dois testes
nativos. O teste de tráfego também confirmou que FORWARD DROP do Docker não
impede a passagem entre LANs gerenciadas nem contorna um bloqueio nft. Downloads
reais das duas bases foram validados em diretório temporário, sem ativar filtros.
