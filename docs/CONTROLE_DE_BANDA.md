# Controle de banda — correção de 24/09/2026

Os endereços deste documento foram substituídos por exemplos de documentação.

## Comportamento

Em Controle de Banda, Aplicar envia os campos da respectiva linha. Um valor
inteiro acima de zero em download ou upload ativa a regra; 0/0 a desativa.
Zero em apenas uma direção deixa essa direção sem limite. Valores negativos,
fracionários ou não numéricos são recusados pela camada web antes de chamar o core.
O servidor calcula enabled a partir dos valores, sem depender de um checkbox.
Cada formulário possui ID único, inclusive quando há dispositivos duplicados.
Os campos usam o atributo form, e o formulário fica dentro da célula do botão.
O indicador considera enabled e os valores; reflete a configuração salva.
A instalação efetiva das regras deve ser conferida com tc no Linux.

## Causa corrigida

O template não enviava enabled, mas web/app.py interpretava sua ausência como
false. Além disso, form era filho direto de tr: o navegador fechava o formulário
antes dos campos e do botão. O indicador da primeira tabela ignorava enabled.
A regra existente 192.0.2.137 / eth1 tinha 20/20 Mbps e enabled=false.

## Rotas e catálogo de acessos existente

Esta instalação independente em /opt/linux-router não possui app.json nem
Config > Usuarios e acessos do NanotechSoft. Nenhuma função, rota, autenticação
ou concessão de acesso foi adicionada. O catálogo existente permanece:

| Função | Web | Core local |
| --- | --- | --- |
| Consultar limites | GET /bandwidth | GET /api/bandwidth |
| Aplicar limite | POST /bandwidth/rule | POST /api/bandwidth/rule |
| Remover limite | POST /bandwidth/delete | POST /api/bandwidth/delete |

O core permanece vinculado a 127.0.0.1:5050. A aplicação web existente não
implementa autenticação por usuário; não há perfis autorizado/não autorizado
para testar neste serviço. As validações existentes de IP/interface no core
foram preservadas. O NanotechSoft em /srv/nanotechsoft não foi alterado.

## Validação e operação

Testes em tests/test_bandwidth.py usam o cliente Flask e core simulado, sem
alterar regras reais: ativação 20/20, 20/0, 0/20; desativação 0/0; rejeição de
valores inválidos; indicadores; associação dos formulários; mensagem de erro.
Executar com as dependências da imagem web (o venv do core não contém requests).
Apenas router-web deve ser reconstruído pelo docker-compose.yml existente.
Não é necessário reiniciar core, interfaces, DHCP ou firewall.
Os arquivos anteriores foram preservados em
/opt/linux-router/backup/bandwidth-fix-20260924-153840.

## Resultado da implantação

Cinco testes passaram em container isolado sem rede, usando as dependências web.
Após reconstruir e recriar somente router-web, o Chrome verificou 30 formulários:
cada um continha os quatro campos e seu botão de envio associados corretamente.
A regra existente de 192.0.2.137 foi reaplicada pelo POST web com 20/20 Mbps,
sem enviar enabled. O core confirmou enabled=true no armazenamento persistente.
O tc confirmou em eth1 a classe HTB 1:10 com rate/ceil 20Mbit, filtro de download
por destino 192.0.2.137 e filtro ingress por origem com police rate 20Mbit.
A interface eth1 permaneceu UP em 192.0.2.2/24 e o core permaneceu ativo.
Não foi realizado teste de saturação/velocidade a partir do aparelho cliente.
