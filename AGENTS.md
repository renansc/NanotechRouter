# Instruções para manutenção

Antes de alterar ou testar, ler README.md, docs/ACESSOS.md e a documentação
da função afetada. Consultar git status e preservar alterações existentes.

- Não versionar dados, credenciais, chaves, backups, leases ou configurações reais.
- Não executar core nem reaplicar regras de rede durante testes de interface.
- Testar com chamadas ao core simuladas e dados sintéticos.
- Manter operações na raiz e usar o docker-compose.yml existente; não criar
  scripts de deploy dentro de core/ ou web/.
- Não restaurar bancos nem sincronizar dados em comandos comuns.
- Mudanças de função devem atualizar documentação, catálogo de acessos,
  validações no servidor e testes. Não conceder acesso implicitamente.
- A instalação é independente e possui admin local por solicitação explícita
  do operador. Ler docs/SEGURANCA_VLAN_ROTAS.md ao alterar autenticação ou rede.
  Uma futura integração ao NanotechSoft deve substituir esse login pelo central,
  reutilizando sessão, manifests e Config > Usuarios e acessos.
