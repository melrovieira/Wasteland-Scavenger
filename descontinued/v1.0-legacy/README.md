Esta é uma versão inicial do código, que na teoria funcionava como um **Credential Dumper**, extraindo logins do banco de dados **Login Data** dos navegadores.

Ela foi descontinuada porque foi desenvolvida com base no sistema antigo de criptografia dos navegadores, que utilizava apenas **DPAPI** para proteger as senhas no banco de dados.  
Atualmente, os navegadores adotaram um esquema mais complexo com **três camadas de criptografia**:

- As senhas no banco de dados são protegidas com **AES**.  
- A chave AES está armazenada no arquivo `Local State.json`, criptografada em **Base64** e protegida por **DPAPI**.

Isso torna o processo de descriptografia e extração de senhas completamente diferente e mais complexo.

Embora esta versão esteja **obsoleta**, parte do código ainda será reaproveitado em futuras versões, que terão novas funcionalidades (não só a extração dos dados do **Login Data**, mas também outras funções de um *Credential Dumper*) e compatibilidade com os métodos atuais de criptografia.

Esta versão acessava diretamente o **Login Data**, descriptografava as senhas e exibia os logins no **prompt de comando** do computador onde é executado, pois foi uma versão de teste.

Após o desenvolvimento, percebi que não funcionava nos navegadores atuais devido às mudanças no sistema de criptografia, o que motivou o desenvolvimento das versões seguintes.
