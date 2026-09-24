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
- A instalação atual é independente e não possui autenticação por usuário.
  Uma futura integração ao NanotechSoft deve reutilizar login e sessão únicos,
  manifests e Config > Usuarios e acessos; não criar login concorrente.
