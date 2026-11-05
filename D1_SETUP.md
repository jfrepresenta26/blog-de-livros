# Ligar o login ao banco do Blog escolar do Gabriel

O login usa Cloudflare Pages Functions e D1. O D1 é um banco dentro da mesma conta Cloudflare e do projeto Pages que já publica o blog; não é preciso criar um projeto Firebase nem contratar outro serviço.

## Configuração única no Cloudflare

1. No painel Cloudflare, abra o projeto Pages `blog-de-livros` e crie um banco D1 na mesma conta.
2. Em **Settings → Bindings**, adicione um binding de D1 com o nome `DB` e selecione esse banco. Salve e faça um novo deploy do projeto.
3. No D1, abra o console SQL e execute o conteúdo de `migrations/0001_auth.sql`.
4. Nas variáveis/segredos do projeto Pages, crie o segredo `BOOTSTRAP_CODE` com um código forte temporário. Faça outro deploy para disponibilizá-lo às Functions.
5. Abra `https://blog-de-livros.pages.dev/setup.html`, informe o código, o e-mail e uma senha forte (mínimo de 12 caracteres). Essa primeira conta será a administradora do Blog do Gabriel.
6. Entre no blog e use **Contas** para convidar outras pessoas e escolher qual blog a conta abre. O código inicial deixa de funcionar depois que a primeira conta é criada; remova o segredo `BOOTSTRAP_CODE` do projeto após a configuração.

As senhas são armazenadas como hashes PBKDF2 e nunca em texto puro. A sessão usa cookie `HttpOnly`, `Secure` e expira após sete dias. Não envie o código inicial ou senhas em mensagens públicas.

## Limite atual

O login e o cadastro de contas ficam no Blog do Gabriel. A conta associada à Débora encaminha para o site dela, que ainda é público e não verifica essa sessão. Para também proteger a página da Débora, o projeto Pages dela precisa receber as mesmas Functions e o binding `DB`.
