# scannerPython

> Ferramenta de scanner de rede inspirada no Nmap para descoberta de hosts, análise de portas e identificação de serviços.
> 
> Desenvolvedores:
>
>  - Daniel Wictor 
>  - Olavo Regis   


---

## Pacotes

- **Python 3.10+**  
- `socket`  
- `asyncio`  
- `concurrent.futures`  
- `argparse`  
- `ipaddress`  
- `json`  
- `re`  
- `logging`  

---

## Guia de Instalacao

Siga os passos abaixo para rodar o scanner localmente:

1. **Clone o repositório**:
    ```bash
    git clone https://github.com/seu-usuario/scannerPython.git
    cd scannerPython
    ```

2. **Crie o ambiente virtual**:
    ```bash
    python3 -m venv venv
    ```

3. **Ative o ambiente virtual**:

   - No **Linux/macOS**:
     ```bash
     source venv/bin/activate
     ```
   - No **Windows**:
     ```bash
     venv\Scripts\activate
     ```

4. **Instale as dependências**:
    ```bash
    pip install --upgrade pip
    pip install -r requirements.txt
    ```

5. **Execute a ferramenta via CLI**:
    ```bash
    python main.py --help
    ```


---

## Funcionalidades

### 1. Descoberta de Hosts
- **ICMP Ping Sweep** para detectar hosts ativos.  
- **TCP SYN Scan** básico para identificar hosts respondendo em portas específicas.  
- **ARP Scan** para rede local (LAN).

### 2. Port Scanning
- **TCP Connect Scan**  
- **TCP SYN Scan**  
- Scan de portas específicas ou por **range** (ex: 1–1024)  
- Scan das **top 100 portas mais comuns**  

### 3. Detecção de Serviços
- **Banner Grabbing**  
- Identificação de protocolos comuns:
  - HTTP
  - FTP
  - SSH
  - SMTP

### 4. Detecção de Versão
- Extração de versão via banner  
- Uso de **regex** para identificar versões conhecidas

### 5. Modos de Execução
- **Rápido:** varredura básica e ágil  
- **Completo:** varredura profunda  
- **Customizado:** escolha de hosts, portas e protocolos  
- **Stealth:** envio de pacotes discretos

### 6. Geração de Relatórios
- Saída formatada no terminal  
- Exportação em **JSON** e **TXT**  
- Opção de salvar relatório em arquivo local

### 7. Controle de Performance
- Timeout configurável  
- Número de threads configurável  
- Delay entre envio de pacotes  

---

## Arquitetura do Projeto

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
