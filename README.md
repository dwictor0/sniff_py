# sniff_py

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Status](https://img.shields.io/badge/status-em%20desenvolvimento-orange)
![License](https://img.shields.io/badge/license-MIT-green)
![Docker](https://img.shields.io/badge/docker-supported-blue)
![CLI](https://img.shields.io/badge/interface-CLI-lightgrey)

> Ferramenta de scanner de rede inspirada no Nmap para descoberta de hosts, análise de portas e identificação de serviços.

---

## Desenvolvedores

- Daniel Wictor
- Olavo Regis

---

# Sumário

- [Visão Geral](#visão-geral)
- [Funcionalidades](#funcionalidades)
- [Tecnologias Utilizadas](#tecnologias-utilizadas)
- [Instalação com Ambiente Virtual (venv)](#instalação-com-ambiente-virtual-venv)
- [Instalação com Docker](#instalação-com-docker)
- [Modo de Uso](#modo-de-uso)
- [Arquitetura do Projeto](#arquitetura-do-projeto)
- [Troubleshooting](#troubleshooting)
- [Melhorias Futuras](#melhorias-futuras)
- [Aviso Legal](#aviso-legal)
- [Licença](#licença)

---

# Visão Geral

O **sniff_py** é uma ferramenta de análise e reconhecimento de redes desenvolvida em Python, inspirada no comportamento do Nmap.

A aplicação permite:

- Descoberta de hosts ativos
- Escaneamento de portas TCP
- Identificação de serviços
- Coleta de banners
- Detecção de versões
- Geração de relatórios

O projeto possui suporte para execução local com `venv` e também via containers Docker.

---

# Funcionalidades

## Descoberta de Hosts

- ICMP Ping Sweep
- TCP SYN Discovery
- ARP Scan para redes locais

## Port Scanning

- TCP Connect Scan
- TCP SYN Scan
- Scan por range de portas
- Scan das 100 portas mais comuns

## Detecção de Serviços

- Banner Grabbing
- Identificação automática de:
  - HTTP
  - FTP
  - SSH
  - SMTP

## Detecção de Versão

- Extração de versão via banners
- Regex para fingerprinting

## Modos de Execução

| Modo | Descrição |
|------|------------|
| Fast | Escaneamento rápido |
| Full | Escaneamento completo |
| Custom | Configuração personalizada |
| Stealth | Escaneamento discreto |

## Relatórios

- Saída formatada no terminal
- Exportação em:
  - HTML

## Controle de Performance

- Timeout customizável
- Controle de threads
- Delay entre pacotes

---

# Tecnologias Utilizadas

- Python 3.10+
- asyncio
- socket
- argparse
- concurrent.futures
- ipaddress
- logging
- json
- re
- Docker

---

# Instalação com Ambiente Virtual (venv)

## 1. Clone o repositório

```bash
git clone https://github.com/seu-usuario/sniff_py.git
cd scannerPython
```

---

## 2. Crie o ambiente virtual

```bash
python3 -m venv venv
```

---

## 3. Ative o ambiente virtual

### Linux/macOS

```bash
source venv/bin/activate
```

### Windows

```bash
venv\Scripts\activate
```

---

## 4. Instale as dependências

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

---

## 5. Instale o projeto localmente

Este passo é necessário para registrar o alias `pyscan`.

```bash
pip install -e .
```

---

## 6. Execute a ferramenta

```bash
pyscan -h
```

ou

```bash
python cli.py -h
```

---

# Instalação com Docker

## Pré-requisitos

Certifique-se de possuir:

- Docker instalado
- Docker daemon em execução

Verifique a instalação:

```bash
docker --version
```

---

## 1. Clone o repositório

```bash
git clone https://github.com/seu-usuario/sniff_py.git
cd scannerPython
```

---

## 2. Build da imagem Docker

```bash
docker compose up -d --build
```

---

## 3. Executar container interativo

```bash
docker exec -it (id container) bash
```

---

## 4. Instalar dependências

Dentro do container:

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

---

## 5. Instalar o projeto em modo editável

Este passo é necessário para registrar o alias `pyscan`.

```bash
pip install -e .
```

---

## 6. Executar a ferramenta

Após instalar com `pip install -e .`, o comando `pyscan` ficará disponível:

```bash
pyscan -h
```

---

## 7. Executar scan básico

```bash
pyscan 127.0.0.1 --host icmp
```

---

## 8. Executar scan com range de portas

```bash
pyscan 127.0.0.1 -p 1-1024
```

---

## 9. Executar scan completo

```bash
pyscan 127.0.0.1 --full
```
---

# Arquitetura do Projeto

```bash
pyscan/
│
├── core/
│   ├── scanner.py
│   ├── host_discovery.py
│   ├── port_scanner.py
│   ├── service_detector.py
│
├── utils/
│   ├── logger.py
│   ├── report.py
│
├── cli.py
├── main.py
├── requirements.txt
├── Dockerfile
└── README.md
```

---

# Troubleshooting

## Alias `pyscan` não reconhecido

Execute:

```bash
pip install -e .
```

---

## Problemas de permissão no Linux

Algumas funcionalidades podem exigir privilégios elevados:

```bash
sudo python main.py
```

ou

```bash
sudo pyscan
```

---

## Docker sem permissões

Caso encontre erros de permissão ao utilizar Docker:

```bash
sudo docker build -t sniff_py .
sudo docker run --rm sniff_py
```

---

# Melhorias Futuras

- [ ] UDP Scan
- [ ] OS Fingerprinting
- [ ] Integração com banco de CVEs
- [ ] Interface Web
- [ ] Exportação XML
- [ ] Suporte IPv6
- [ ] Dashboard em tempo real

---

# Aviso Legal

Esta ferramenta foi desenvolvida exclusivamente para fins educacionais e testes autorizados.

O uso indevido contra redes ou sistemas sem autorização pode violar leis locais.

---

# Licença

Este projeto é distribuído sob a licença MIT.
