# Reservas DHCP, NAT e acesso ao painel

## Reservas de IP

Em **DHCP / Reservas de IP**, escolher a LAN, informar MAC, IP e nome opcional.
Também é possível preencher o formulário pelo botão Reservar IP de um cliente.
Cada reserva pode ser editada e excluída. O servidor impede MAC inválido,
endereço fora da LAN, gateway, rede/broadcast, MAC/IP duplicado na mesma LAN,
ID de edição inexistente e IP ainda concedido a outro MAC pelo DHCP.
O nome aceita somente letras, números e hífens, até 63 caracteres.

O arquivo local `data/dhcp_reservations.json` é a fonte das reservas. Ele não
é versionado. As linhas `dhcp-host` são geradas em um bloco identificado na
configuração dnsmasq da interface. Ao salvar, o servidor valida a sintaxe antes
de reiniciar somente a instância DHCP afetada; não altera IPs, rotas, NAT, QoS
nem leases existentes. Falhas de validação preservam tudo; falha de inicialização
restaura a configuração anterior e tenta reativá-la, informando eventual erro.
A configuração é reaproveitada no boot e ao reconfigurar a LAN.

Pode-se reservar um IP fora do intervalo dinâmico, desde que pertença à LAN e
esteja livre. A aplicação verifica reservas e leases ativos; ela não consegue
provar que um IP manual de um aparelho desligado está livre. O cliente deve
renovar o DHCP para receber a reserva. Configuração de IP manual e MAC privado
rotativo exigem ajuste no próprio aparelho. A reserva não modifica o firmware.

A instância DHCP é reiniciada brevemente ao alterar reservas, pois as linhas
`dhcp-host` ficam na configuração principal. O dnsmasq não relê essa configuração
com SIGHUP. Referência: [manual oficial do dnsmasq](https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html).

## Cadastro e edição de NAT

**NAT / Port Forward > Editar** carrega a regra existente no formulário. Salvar
preserva seu ID, sem criar duplicação. É possível mudar nome, protocolo, porta
externa, destino, porta interna e ativação. O servidor rejeita edição inexistente,
protocolo inválido, porta fora de 1–65535, duplicação de protocolo/porta externa,
portas TCP 5000/5050 de gerenciamento e destino que não seja aparelho de uma LAN.
Falhas ao aplicar restauram a configuração de regras anterior e tentam reaplicá-la.

O erro 500 original era causado pelo template NAT lendo `download_mbps` e
`upload_mbps`, campos que pertencem ao controle de banda. O indicador NAT agora
usa `enabled`. Essa correção já existia no host e foi incorporada ao Git.

O DNAT é aplicado à entrada WAN. A chain DOCKER-USER recebe liberação do fluxo
de entrada e do retorno estabelecido, limitado à direção REPLY e porta externa
original no conntrack, inclusive
quando a política FORWARD do Docker é DROP. O aparelho interno deve usar o
roteador como gateway. Este fluxo não implementa NAT loopback/hairpin para
clientes LAN acessarem a porta externa; na LAN, usar o IP interno do serviço.

## Rotas locais e Tailscale

O diagnóstico capturou uma requisição entrando pela WAN e chegando ao aparelho
interno. A resposta era desviada para tailscale0 porque uma rota importada da
mesma sub-rede tinha precedência sobre a rota diretamente conectada.

`prefer_connected_routes` consulta as redes conectadas na tabela main das
interfaces WAN/LAN cadastradas e cria regras de destino com prioridade 2500,
tabela main e protocolo 242. Só remove regras desse mesmo identificador quando
a rede deixa de ser diretamente conectada. Não desativa a Tailscale nem modifica
as regras ou outras rotas dela. A aplicação é idempotente e ocorre ao configurar
WAN/LAN, salvar/remover NAT e no fluxo de reaplicação do serviço de boot existente.

A prioridade menor que as regras da Tailscale segue a
[documentação oficial sobre redes sobrepostas](https://tailscale.com/docs/reference/troubleshooting/network-configuration/lan-traffic-overlapping-subnets).
A regra aplicada manualmente durante o diagnóstico usa o mesmo identificador
do código, sem criar um segundo mecanismo persistente. Mudanças externas no IP
da interface exigem reaplicar a configuração ou reiniciar pelo fluxo existente.

## Acesso ao painel

Usar `http://<IP-do-gateway>:5000` na LAN e `http://<IP-WAN>:5000` na rede de gestão
externa. A página DHCP mostra um link com o gateway de cada LAN. O core continua
em 127.0.0.1:5050; o painel permanece sem autenticação individual, conforme
[catálogo de acessos](ACESSOS.md), sob as restrições de rede da instalação.

O Gunicorn web usa dois workers gthread com quatro threads cada. Os logs
registraram workers síncronos esperando conexões que não enviavam uma requisição
HTTP, até o timeout. Em teste isolado, duas conexões ociosas bloquearam o modelo
antigo; o novo modelo continuou atendendo. Isso não altera a porta nem a API.

## Verificação

- `tests/test_network_management.py`: CRUD, validação e rollback DHCP/NAT,
  edição sem duplicação, prioridades locais idempotentes, retorno estabelecido
  e telas com dados reais de formato, usando endereços sintéticos e comandos simulados.
- `tests/test_bandwidth.py`: regressão dos limites de banda.
- Sintaxe da configuração de reserva verificada pelo dnsmasq real com `--test`,
  sem iniciar um serviço DHCP de teste na rede real.
- Captura de pacotes comprovou o desvio do retorno; após priorizar a rede local,
  o painel e o redirecionamento TCP externo retornaram HTTP 200.
- O usuário confirmou que o painel da LAN voltou a abrir normalmente.

Nenhuma reserva foi inventada para aparelhos reais. Testes não liberam concessões
nem alteram os endereços dos clientes. Dados e segredos continuam fora do Git.

## Validação final da implantação

Os 20 testes automatizados passaram. `tests/check_firewall_native.py` aplicou,
reaplicou e removeu regras TCP/UDP com iptables/nft reais em namespace isolado.
O script recusa execução na rede principal do host; executar explicitamente com
`sudo unshare --net core/venv/bin/python tests/check_firewall_native.py`.

A edição da regra existente foi enviada pela interface instalada, mantendo ID,
porta e destino. O painel NAT e a tela de reservas responderam HTTP 200, assim
como o serviço interno acessado pela porta externa. Uma tentativa de reservar
o próprio gateway foi recusada pelo core com HTTP 400. A interface foi
inspecionada no Chrome. Nenhuma reserva de aparelho real foi criada durante a
validação, e não foi preciso reiniciar interfaces nem o serviço DHCP.
