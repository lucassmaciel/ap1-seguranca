# Sistema de Mensagens Instantâneas com Criptografia

Este sistema visa a criação de um sistema de mensagens instantâneas que permite a comunicação em pares (ponto a ponto) e em grupo.

Para garantir o princípio de confidencialidade, será utilizado o algoritmo Salsa20, implementado em Python com a biblioteca `pycryptodome`.

## Como funciona o Salsa20?

Ele atua como uma cifra de fluxo, que é um método de criptografia no qual os dados são criptografados byte a byte. Uma chave criptográfica e um algoritmo são aplicados a cada dígito binário em um fluxo de dados de texto simples para produzir texto cifrado. A cifra de fluxo oferece como maior vantagem a velocidade, sendo ideal para dados em tempo real como mensagens instantâneas.

*Fonte: [techtarget](https://www.techtarget.com/searchsecurity/definition/stream-cipher)*

## Componentes Mandatórios

Para a implementação da camada de confidencialidade, os seguintes componentes são mandatórios:

* **O algoritmo:** Salsa20
* **A chave:** Uma chave de 32 bytes que deve ser única por sessão de comunicação ou par de usuários.
* **Nonce (Número de uso único):** Um valor de 24 bytes, gerado aleatoriamente para cada mensagem individual.

## Workflow do Remetente

1.  **Obtenção da Chave:** Acessar a chave secreta de 32 bytes compartilhada com o destinatário.
2.  **Geração do Nonce:** Gerar 24 bytes de dados aleatórios a partir de uma fonte criptograficamente segura. Este será o nonce da mensagem.
3.  **Inicialização do Cifrador:** Instanciar o cifrador Salsa20 com a chave secreta e o nonce recém-gerado.
4.  **Criptografia:** Aplicar o cifrador ao texto plano da mensagem para produzir o texto cifrado (ciphertext).
5.  **Formatação do Pacote:** Montar o pacote de dados a ser transmitido pela rede. O destinatário precisa do nonce para descriptografar a mensagem. Portanto, o formato do pacote será:
    `[ Nonce de 24 bytes ] + [ Texto Cifrado (tamanho variável) ]`

## Workflow do Destinatário

1.  **Recebimento do Pacote:** Receber o fluxo de bytes da rede.
2.  **Extração dos Componentes:** Separar o pacote recebido:
    * Os primeiros 24 bytes são o Nonce.
    * O restante dos bytes é o Texto Cifrado.
3.  **Obtenção da Chave:** Acessar a chave secreta de 32 bytes compartilhada com o remetente.
4.  **Inicialização do Cifrador:** Instanciar o cifrador Salsa20 com a chave secreta e o nonce extraído do pacote.
5.  **Descriptografia:** Aplicar o cifrador ao texto cifrado para recuperar o texto plano original.