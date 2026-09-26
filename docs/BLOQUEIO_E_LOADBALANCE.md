# Página de bloqueio e Load Balance (0.6.0)

## Página para sites bloqueados

Em **Firewall > Página de bloqueio**, o administrador pode definir título e
mensagem e habilitar atendimento HTTP e HTTPS. O recurso atua somente nos
domínios bloqueados pelo filtro DNS do NanotechRouter. O DNS responde
`198.18.0.1`, endereço local mantido no loopback do roteador, e o serviço
retorna HTTP 451. Texto configurado e hostname são escapados antes de entrar no
HTML. A página não executa JavaScript e envia CSP, `no-store` e `nosniff`.

O firewall limita 80/443 desse endereço às interfaces LAN e à origem escolhida
no perfil. Equipamentos dispensados do filtro DNS continuam usando seu DNS
normal. Quando o firewall, o filtro DNS ou a página estiver desativado, o
serviço é parado; as regras negam acesso ao endereço e o modo antigo NXDOMAIN
é mantido quando a página está desmarcada.

### HTTPS e CA local

Antes de distribuir o certificado, clique **Preparar certificado** e depois
**Baixar certificado CA**. A chave privada fica em
`data/blockpage/ca.key`, modo 0600, e nunca é enviada pelo endpoint. Instale o
arquivo público `nanotechrouter-block-page-ca.crt` como autoridade confiável
somente em celulares e computadores administrados. Em alguns sistemas também
é necessário habilitar manualmente a confiança completa dessa CA.

O serviço gera sob demanda um certificado com SAN para o domínio solicitado,
assinado pela CA local, e conserva no máximo 500 certificados. Sem confiar na
CA, o navegador encerra o TLS com aviso antes de receber a página. Aplicativos
com certificate pinning ou que recusam CAs de usuário também podem mostrar
falha de conexão. HSTS não elimina a página quando a CA é confiável, mas erros
de confiança não podem ser substituídos por HTML. DNS sobre HTTPS na porta 443,
IPs fixos e equipamentos fora da política podem contornar o redirecionamento;
as limitações dos filtros continuam válidas.

O serviço systemd é `nanotechrouter-blockpage.service`. Ele não deve ser
habilitado para iniciar sozinho: o core o inicia ou para de acordo com a
política persistida em `data/firewall.json`. O certificado e a chave pertencem
à instalação e não entram no Git nem devem ser copiados entre clientes.

## Load Balance e failover

Em **Balanceamento de Links**, cadastre cada interface WAN com seu gateway,
peso e prioridade. A interface precisa ter IPv4 no host, não pode ser LAN e o
gateway precisa pertencer à rede diretamente conectada. Uma interface só pode
aparecer uma vez. O sistema exige ao menos dois membros habilitados antes de
ativar o recurso.

Os modos disponíveis são:

- **Balancear por peso:** cada conexão nova de uma LAN com Internet recebe uma
  WAN saudável de forma aleatória ponderada. Peso 2 e peso 1 tendem a uma razão
  2:1 ao longo de muitas conexões. Uma única transferência não soma a banda dos
  links e permanece na WAN escolhida.
- **Somente failover:** novas conexões usam a WAN saudável de menor prioridade.
  Quando ela falha, a próxima prioridade assume.

O alvo de saúde é um IPv4 informado pelo administrador. Cada link possui tabela
de rotas e marca próprias; o ping é enviado por essa tabela. O timer
`nanotechrouter-loadbalance-health.timer` verifica a cada 30 segundos. Se todos
os testes falharem, novas conexões deixam de receber marca e a rota principal
do Linux continua como contingência. O tráfego iniciado pelo próprio roteador
continua usando a rota principal.

O balanceamento usa conntrack para manter todos os pacotes de uma conexão no
mesmo link. Conexões recebidas por uma WAN, inclusive Port Forward, guardam a
WAN de entrada; a resposta do servidor interno volta pelo mesmo provedor. NAT,
FORWARD e redirecionamentos são aplicados a todas as WANs habilitadas. O sistema
configura `rp_filter=2` e `src_valid_mark=1`, necessários para retorno assimétrico
válido em múltiplos provedores. Somente a tabela nft `ip nanotechrouter_lb`, as
regras `ip rule` de prioridade 2600/protocolo 244 e as tabelas 42001–42200 são
gerenciadas; tabelas e regras de VPN ou outros programas são preservadas.

As configurações ficam em `data/loadbalance.json` e o último estado em
`data/loadbalance_status.json`. Salvamento e aplicação são transacionais: uma
falha tenta restaurar arquivo, tabelas, NAT, FORWARD e Port Forward anteriores.
O cadastro não configura modem, autenticação PPPoE, DHCP de operadora ou IPv6.
Cada modem/link deve estar operacional e fornecer um IPv4 à interface antes do
cadastro. IPv6 não participa do balanceamento nesta versão.

## Validação

Os testes unitários usam dados sintéticos e chamadas de rede simuladas. Os
checkers nativos recusam o namespace principal. `check_blockpage.py` valida
HTTP 451, escape de HTML, CA, SNI e HTTPS confiável/não confiável em portas
temporárias. `check_loadbalance_native.py` cria três namespaces temporários e
valida distribuição ponderada, falha de link, prioridade e Port Forward na WAN
secundária. Execute o teste nativo apenas em ambiente isolado:

```bash
sudo unshare --net core/venv/bin/python tests/check_loadbalance_native.py
```
