# Operação do piloto local

A classificação é **LOCAL SELF-HOSTED PILOT — DEVELOPMENT CERTIFICATION AUTHORITY**.
O [README](../../README.md) é o caminho de primeira utilização. Este documento
complementa os limites de processo, custódia e recuperação do [ADR 0070](../adr/0070-local-pilot-identity-and-provisioning.md).
M9 permanece INCOMPLETE. M10, M11, Pre-Genesis e Genesis não começaram.

## Inventário de serviços e capacidades

| Componente | Ciclo de vida | Capacidades e dependências |
| --- | --- | --- |
| PostgreSQL dedicado | Sempre ativo durante operação | Metadados duráveis; imagem fixada; dados privados fora do código; conexão local com senha |
| Migration executável | Apenas `init`/`update` explícitos | Papel proprietário de DDL, separado do controle e observação; falhas não autorizam downgrade |
| `archcert-local-api` | Serviço supervisionado | Contas Argon2id, inicialização, projetos próprios, projeções privadas e admissão existente; sem runner/assinador |
| `archcert-panel` / Glassmere | Serviço supervisionado | SELECT nas tabelas autorizadas, verificação pública e broker local limitado; sem tabelas de senha, socket OCI ou chave privada |
| OpenSSH / Northgate | Serviço supervisionado | Chave pública, forced command restrito, grants exatos, quarentena e snapshot imutável; sem execução de alvo |
| `archcert-controller run-once` | Processo confiável sob demanda | Fila durável, leases, gates, reconciliação, publicação de evidências e assinatura somente após elegibilidade |
| `archcert-worker` | Filho do controlador | Entrada privada por stdin; ambiente limpo; sem credencial de banco, aquisição, objetos ou assinatura |
| Runner / daemon rootless | Pré-requisito independente | Execução com fonte somente leitura, rede negada e limites; nunca é o socket montado no painel |
| Store de evidências | Diretório privado persistente | Objetos imutáveis por projeto/digest; staging/available e leitura verificada |
| Chave Ed25519 de desenvolvimento | Custódia privada do host | Provisionamento explícito; controlador recebe caminho, painel recebe somente chave pública |
| Sessões do painel | Memória do processo | Tokens opacos, expiração, logout e revisão de grants; reiniciar encerra sessões e mantém contas |
| API `archcertd` / command broker original | Opcional, provisionamento original | API e comandos Glassmere preservados; não necessário no caminho local alternativo de admissão |
| Provedores semânticos | Opcionais, fora do onboarding | Replay/unavailable existentes; nenhuma divulgação externa automática |
| M6 / Release Permit | Operação de autoridade separada | Somente receita e escopo documentados; não disponível no assistente Python |
| Scripts de demonstração/testes | Apenas engenharia | Não iniciados como serviços e não usados como banco permanente do piloto |

O supervisor coordena um host. O banco continua sendo a fila e o controlador
existente mantém a autoridade de execução. Morte do navegador não libera lease;
morte do worker não comprova limpeza. O loop respeita a reconciliação de startup
e não faz `docker prune`, remoção global ou reset de claims/gates.

## Armazenamento e permissões

`ARCHCERT_LOCAL_HOME` é privado (0700), fora do repositório. Arquivos privados são
0600; executáveis instalados são 0700. A implantação mantém:

| Diretório | Conteúdo |
| --- | --- |
| `database/` | Volume PostgreSQL; ownership interno pode ser o usuário do container |
| `artifacts/` | Evidência e certificados imutáveis |
| `sources/` | Quarentena, sessões e snapshots Northgate; limite original de 32 sessões retidas |
| `config/` | Configuração de autoridade, projeções, broker e senhas independentes de infraestrutura |
| `bootstrap/` | Entrega privada de setup e arquivos temporários de recuperação |
| `git/` | Host key, host pin, authorized_keys e configuração SSH restrita |
| `signing/` | Chave privada de desenvolvimento; não é segredo do painel/runner |
| `public/` | Âncora pública de verificação selecionada pelo host |
| `workspaces/`, `workspaces.runtime/` | Workspaces isolados e gates/tombstones persistentes |
| `audit/` | Auditoria privada do painel; auditoria durável de identidade/projeto também está no PostgreSQL |
| `health/` | Observação operacional com instante; não é evidência de certificação |
| `run/` | Coordenação/PIDs/marcador de atualização; sem autoridade derivada de PID isolado |
| `logs/` | Logs privados; inspecionar localmente |
| `backups/` | Backup completo privado, incluindo credenciais e custódia |
| `bin/` | Executáveis construídos da fonte selecionada e digests no manifesto |

A conexão de observação não pode autenticar com a senha do controle: são valores
independentes. O papel de controle não possui DDL, atualização do registro de
migrations nem UPDATE de auditoria. Os triggers e transações preservam seus
invariantes; administrador do banco e mesma UID/root continuam confiáveis neste
piloto. Os diretórios não substituem isolamento entre usuários de sistema em produção.

## macOS / Colima observado

O daemon Docker comum do perfil `default` mantém o banco. O runner usa o serviço
**rootless já provisionado** do perfil separado `archcert-m3`. Apenas iniciar uma
VM Colima comum não provisiona automaticamente esse serviço e não o qualifica.

Os comandos de diagnóstico usados nesse ambiente são:

```bash
colima start archcert-m3
colima ssh --profile archcert-m3 -- systemctl --user status docker --no-pager
```

O socket do serviço observado é `/run/user/501/docker.sock`. O usuário/endpoint
precisam ser selecionados conforme o provisionamento real da VM. No ambiente
observado, um encaminhamento local privado pode ser criado com:

```bash
mkdir -p "$HOME/.local/share/archcert-runtime"
chmod 700 "$HOME/.local/share/archcert-runtime"
ssh -F "$HOME/.colima/ssh_config" -fNT \
  -L "$HOME/.local/share/archcert-runtime/rootless.sock:/run/user/501/docker.sock" \
  -o ExitOnForwardFailure=yes colima-archcert-m3
export ARCHCERT_RUNTIME_ENDPOINT="unix://$HOME/.local/share/archcert-runtime/rootless.sock"
export ARCHCERT_DOCKER="$(command -v docker)"
```

Esse encaminhamento e a VM são pré-requisitos independentes; `down` do piloto não
para daemons compartilhados nem apaga sockets desconhecidos. Um socket já ocupado
é motivo para inspecionar o processo selecionado, não para remover o arquivo às
cegas. O diagnóstico real é:

```bash
"$ARCHCERT_LOCAL_HOME/bin/archcert-worker" \
  --docker "$ARCHCERT_DOCKER" --endpoint "$ARCHCERT_RUNTIME_ENDPOINT" doctor
```

A execução macOS/Colima é DEVELOPMENT TESTED / UNQUALIFIED para qualificação
nativa. Consulte o perfil Linux retido para a diferença exata. Inventários
observados não são attestation criptográfica do daemon, host ou toolchain.

## Recuperação e atualização

`init` recusa diretório preenchido/instância existente. Uma interrupção não é
permissão para apagar estado e começar novamente. `renew-setup` só renova segredo
não consumido. Depois de INITIALIZED, use `recover-password` para acesso perdido.

Mutação de identidade/projeto e auditoria são transacionais. Configurações são
projeções reconstruíveis, com marcador durável de publicação pendente. Para uma
publicação interrompida, preserve auditoria/arquivos e execute:

```bash
./scripts/archcert-local down
./scripts/archcert-local publish
./scripts/archcert-local up
```

`publish` inicia explicitamente o PostgreSQL selecionado antes de reconstruir
as projeções; não inicia o painel, runner ou assinador. Não edite linhas de conta,
gerações, digests ou migrations manualmente para conseguir uma resposta favorável.

Backups devem incluir todo o conjunto descrito no README. A restauração usa outra
instalação e mantém execução desabilitada até revisão explícita. A assinatura de
um certificado pode ser verificada sem reativar runtime ou chaves privadas.
Não restaure gates de um host em outro e suponha que claims antigos autorizam
execução; recursos e bindings precisam ser investigados segundo Stoneward.

## Evidência de aceitação

Os resultados desta entrega são registrados após a execução dos testes na fonte
selecionada. Os logs, capturas de navegador, certificados de desenvolvimento e
relatórios transitórios ficam sob `target/local-pilot/`, fora do versionamento.
Histórico M6–M9 não constitui um novo resultado da instalação local.

Este documento não atribui PASS a testes planejados. A entrega só pode ser chamada
COMPLETE para o recorte local quando cadastro, autenticação, projeto, ingresso real,
admissão, execução, persistência, emissão legítima e verificação offline tiverem
evidência correspondente. Caso contrário, permanece INCOMPLETE com bloqueios explícitos.

> This is engineering self-validation under a shared implementation/authority context. It is not independent certification and does not replace Genesis / Firstwarden.
