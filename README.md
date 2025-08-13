# 🛡️ Black Knight - Open Redirect Scanner

&#x20;      &#x20;

**Black Knight** é uma ferramenta avançada para detecção de **Open Redirect**, coletando URLs e subdomínios de múltiplas fontes e testando automaticamente todos os parâmetros com payloads avançados.

---

## ⚡ Funcionalidades

- 🔹 Coleta de **subdomínios** via [C99.nl](https://subdomainfinder.c99.nl/)
- 🔹 Coleta de URLs de:
  - **Wayback Machine**
  - **DuckDuckGo**
  - **Bing**
- 🔹 **Crawler** interno para seguir links coletados
- 🔹 Teste de **payloads avançados de Open Redirect**
- 🔹 Logs em tempo real:
  - `[COLETADA]` → URL coletada
  - `[VULNERÁVEL]` → URL vulnerável
  - `[SEGURO]` → URL segura
- 🔹 Multithreading para maior eficiência
- 🔹 Geração de relatórios: CSV/TXT

---

## 🎬 Demonstração

\
*Exemplo de execução do Black Knight, mostrando coleta e testes de URLs.*

---

## 🛠️ Requisitos

- Python 3.10+
- Bibliotecas Python:

```bash
pip install requests beautifulsoup4
```

---

## 🚀 Uso

### Testando uma URL única

```bash
python3 black-knight.py -u https://exemplo.com -v
```

### Testando uma lista de URLs

```bash
python3 black-knight.py -l urls.txt -v
```

### Parâmetros

| Flag | Descrição                             |
| ---- | ------------------------------------- |
| `-u` | URL única para teste                  |
| `-l` | Arquivo com lista de URLs             |
| `-v` | Modo verbose (mostra logs detalhados) |

---

## 📄 Estrutura de saída

- `vulnerable_urls.csv` → CSV detalhado com:
  - URL
  - Parâmetro testado
  - Payload
  - Status code
  - Location
- `vulnerable_urls.txt` → Apenas URLs vulneráveis
- `safe_urls.txt` → URLs seguras

---

## ⚠️ Aviso Legal

Essa ferramenta deve ser utilizada **apenas em domínios autorizados**.\
O uso em sistemas sem permissão é **ilegal** e pode resultar em consequências legais.

---

## 📌 Contribuições

Pull requests e sugestões são bem-vindos.\
Para contribuir:

1. Faça um fork do repositório
2. Crie uma branch (`git checkout -b minha-feature`)
3. Commit suas alterações (`git commit -m 'Adiciona nova feature'`)
4. Push para a branch (`git push origin minha-feature`)
5. Abra um Pull Request

---

## 💖 Doações

Se você quiser apoiar o desenvolvimento de scripts para Red Team, pode fazer uma doação via **PIX**: `16303802702`\
Agradecemos muito pelo seu apoio! 🙏

---

## 🔗 Referências

- [Wayback Machine API](http://web.archive.org/)
- [C99.nl - Subdomain Finder](https://subdomainfinder.c99.nl/)
- [DuckDuckGo HTML Search](https://html.duckduckgo.com/html/)

---

Feito com ❤️ por **https://www.linkedin.com/in/yuri-assis-074a66200/**

