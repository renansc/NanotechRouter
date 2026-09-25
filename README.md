# NanotechRouter

Gerenciador de roteador Linux com interface web para WAN/LAN, DHCP,
dispositivos, apelidos de portas, NAT, redirecionamento de portas, controle
de banda por IPv4, VLANs, rotas estáticas, firewall e administração com login. Código extraído da instalação em `/opt/linux-router`,
incluindo a correção do controle de banda e as reservas DHCP/edição de NAT.

## Estrutura

- `core/core.py`: API Flask local, executada no host com privilégios de rede.
- `web/`: interface Flask/Gunicorn executada em Docker com rede do host.
- `deploy/systemd/`: unidades existentes do core e da reaplicação no boot.
- `deploy/nanotechrouter-safe-restore`: cópia do utilitário já instalado no host.
- `tests/`: testes isolados da interface, sem alterar a rede.
- `docs/CONTROLE_DE_BANDA.md`: diagnóstico, correção e validação do limite.
- `docs/REDE_NAT_DHCP.md`: reservas, edição de NAT, rotas locais e acesso ao painel.
- `docs/ACESSOS.md`: catálogo das funções e das rotas existentes.

`data/`, `config/`, bancos, leases DHCP, logs, backups, ambientes virtuais,
arquivos `.env` e chaves SSH pertencem à instalação e não são versionados.
Clonar este projeto não copia a configuração de rede de outro equipamento.

## Dependências

Host Linux com Python 3, suporte a venv, Docker/Compose, `ip`/`tc` (iproute2),
`nft`, `iptables`, `dnsmasq`, `nmap`, `curl`, `jq` e systemd. O core espera o
diretório `/opt/linux-router`, usa nftables para NAT e a chain `DOCKER-USER`
para encaminhamento. As dependências Python estão nos dois requirements.txt.

A interface utiliza a porta 5000 e chama o core em `127.0.0.1:5050`.
Use Gunicorn com as configurações fornecidas no Dockerfile e no serviço do core.

## Chave da aplicação

A versão preparada para Git exige `ROUTER_SECRET_KEY` no ambiente, substituindo
a constante de assinatura de sessão que existia no código. O Compose lê essa
variável de `.env`; o arquivo real não pode ser enviado ao Git.

Para gerar `.env` em uma instalação nova, sem sobrescrever um arquivo existente:

```bash
python3 - <<'PY'
import os
import secrets
fd = os.open('.env', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'w') as target:
    target.write('ROUTER_SECRET_KEY=' + secrets.token_hex(32) + '\n')
    target.write('ROUTER_API_TOKEN=' + secrets.token_hex(32) + '\n')
PY
```

Em uma instalação que já possui `.env`, acrescentar a variável preservando
as outras configurações. Esta preparação para Git não implanta automaticamente
a mudança na instalação de origem. A chave deve estar configurada antes de
implantar essa versão. Trocar a chave invalida cookies antigos da interface.

## Operação da instalação existente

Antes de atualizar código, preservar os diretórios de dados, configuração e
backups do host. O Compose opera somente a interface web. A partir da raiz:

```bash
docker compose build router-web
docker compose up -d --no-deps --no-build router-web
```

O core é operado pela unidade `linux-router-core.service`, que executa
`/opt/linux-router/core/venv/bin/gunicorn --workers 1 --bind 127.0.0.1:5050 core:app`.
Não reiniciar o core como parte de uma alteração somente na interface.
As unidades e o utilitário em `deploy/` são referências da instalação existente;
não há instalador automático neste repositório.

O serviço `nanotechrouter-safe-restore.service` reaplica LAN/DHCP/NAT/QoS no boot
a partir dos arquivos locais. Não restaura banco nem importa dados de backups.
Sua execução altera a rede e não faz parte dos testes nem do envio ao Git.

## Testes sem alterar o roteador

```bash
python3 -m venv .venv
.venv/bin/pip install -r web/requirements.txt
.venv/bin/python -m unittest discover -s tests -v
```

Os testes usam dados sintéticos e simulam as chamadas ao core. Não iniciar o
core nem chamar `/api/system/reapply` para validar alterações na interface.

## Escopo atual

Valores positivos em download/upload ativam o limite; `0/0` o desativa.
O download usa HTB e o upload usa policiamento de ingress nas LANs cadastradas.
O indicador representa a configuração salva, não uma medição de velocidade.
Detalhes e limitações em [Controle de banda](docs/CONTROLE_DE_BANDA.md).

Esta instalação independente possui login local: **admin / admin** no primeiro
acesso, com troca obrigatória antes de administrar a rede. A senha é persistida
em hash e não é redefinida em atualizações. Configure também `ROUTER_API_TOKEN`
aleatório no `.env` para autenticar painel/core/boot; preserve a chave existente.
O painel permanece HTTP na porta 5000; use a rede de gestão ou Tailscale.

VLANs, rotas estáticas, firewall, filtros DNS e Sistema / Configuração possuem
fluxos funcionais. Os novos bloqueios começam desativados e são configurados
pelo operador na interface. Consulte [Administração e segurança](docs/SEGURANCA_VLAN_ROTAS.md)
para uso, persistência, dependências e limites dos filtros. Versão atual: 0.5.0.

## Reservas e NAT (25/09/2026)

DHCP / Reservas de IP permite cadastrar, editar e remover reservas MAC/IP.
O cliente aplica a reserva ao renovar o DHCP. NAT / Port Forward permite editar
regras existentes sem duplicá-las; o retorno às redes diretamente conectadas
recebe prioridade sobre rotas VPN sobrepostas. O painel continua na porta 5000.
Detalhes, validações, persistência e testes: [Rede, NAT e DHCP](docs/REDE_NAT_DHCP.md).

O NAT também oferece loopback: clientes LAN podem usar a porta externa no IP
WAN ou no gateway LAN do roteador. O retorno na mesma sub-rede é traduzido
para manter a conexão. As regras de isolamento do firewall continuam valendo.
