🛡️ Black Knight - Open Redirect Scanner







 


Black Knight é uma ferramenta avançada para detecção de Open Redirect, coletando URLs e subdomínios de múltiplas fontes e testando automaticamente todos os parâmetros com payloads avançados.

⚡ Funcionalidades

🔹 Coleta de subdomínios via C99.nl

🔹 Coleta de URLs de:

Wayback Machine

DuckDuckGo

Bing

🔹 Crawler interno para seguir links coletados

🔹 Teste de payloads avançados de Open Redirect

🔹 Logs em tempo real:

[COLETADA] → URL coletada

[VULNERÁVEL] → URL vulnerável

[SEGURO] → URL segura

🔹 Multithreading para maior eficiência

🔹 Geração de relatórios: CSV/TXT

🎬 Demonstração

Exemplo de execução do Black Knight, mostrando coleta e testes de URLs.

🛠️ Requisitos

Python 3.10+

Bibliotecas Python:

pip install requests beautifulsoup4

🚀 Uso

Testando uma URL única

python3 black-knight.py -u https://exemplo.com -v

Testando uma lista de URLs

python3 black-knight.py -l urls.txt -v

Parâmetros

Flag

Descrição

-u

URL única para teste

-l

Arquivo com lista de URLs

-v

Modo verbose (mostra logs detalhados)

📄 Estrutura de saída

vulnerable_urls.csv → CSV detalhado com:

URL

Parâmetro testado

Payload

Status code

Location

vulnerable_urls.txt → Apenas URLs vulneráveis

safe_urls.txt → URLs seguras

⚠️ Aviso Legal

Essa ferramenta deve ser utilizada apenas em domínios autorizados.O uso em sistemas sem permissão é ilegal e pode resultar em consequências legais.

📌 Contribuições

Pull requests e sugestões são bem-vindos.Para contribuir:

Faça um fork do repositório

Crie uma branch (git checkout -b minha-feature)

Commit suas alterações (git commit -m 'Adiciona nova feature')

Push para a branch (git push origin minha-feature)

Abra um Pull Request

🔗 Referências

Wayback Machine API

C99.nl - Subdomain Finder

DuckDuckGo HTML Search

Feito por https://www.linkedin.com/in/yuri-assis-074a66200/


💖 Doações

Se você quiser apoiar o desenvolvimento de mais scripts para Red Team, pode fazer uma doação via PIX: 16303802702
