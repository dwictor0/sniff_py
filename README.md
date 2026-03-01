# scannerPython

Projeto de scanner de rede em Python inspirado no Nmap.

O objetivo é desenvolver uma ferramenta capaz de:

- Descobrir hosts ativos
- Escanear portas
- Identificar serviços
- Detectar versões básicas
- Gerar relatórios

---

# Objetivo do Projeto

Criar um scanner de rede modular, orientado a objetos e executável via linha de comando (CLI), com funcionalidades semelhantes ao Nmap.

---

# Requisitos Funcionais (RF)

## RF01 – Descoberta de Hosts

- ICMP Scan (Ping Sweep)
- TCP SYN Scan básico
- ARP Scan (rede local)

---

## RF02 – Port Scanning

- TCP Connect Scan
- TCP SYN Scan
- Scan de portas específicas
- Scan por range (ex: 1–1024)
- Scan de top ports (ex: 100 portas mais comuns)

---

## RF03 – Detecção de Serviços

- Banner Grabbing
- Identificação por resposta padrão
- Identificação básica de protocolo:
  - HTTP
  - FTP
  - SSH
  - SMTP

---

## RF04 – Detecção de Versão (Simplificada)

- Extração de versão via banner
- Uso de Regex para identificar versões conhecidas

---

## RF05 – Modos de Execução

- Modo rápido
- Modo completo
- Scan customizado via argumentos CLI
- Modo Stealth

---

## RF06 – Geração de Relatórios

- Output formatado no terminal
- Exportação em JSON
- Exportação em TXT
- Opção de salvar relatório em arquivo

---

## RF07 – Controle de Performance

- Timeout configurável
- Número de threads configurável
- Delay entre envio de pacotes

---

# Requisitos Não Funcionais (RNF)

- Código modular
- CLI amigável (`argparse` ou `typer`)
- Execução em Linux
- Estrutura orientada a objetos
- Tratamento robusto de exceções
- Sistema de logs detalhados
- Execução com privilégios opcionais (raw sockets)

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
└── requirements.txt  
```

# Pacotes Utilizados
- socket
- asyncio
- concurrent.futures
- argparse
- ipaddress
- json
- re
- logging
# Aviso Legal

Esta ferramenta deve ser utilizada apenas em ambientes autorizados.  
O uso indevido pode violar leis locais e internacionais.
