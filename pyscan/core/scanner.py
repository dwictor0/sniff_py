class ScanConfig:
    """
    Representa a configuração global de performance utilizada pelo scanner.

    Esta classe centraliza parâmetros que impactam diretamente o comportamento
    e desempenho das varreduras executadas pelo sistema.

    Parâmetros controlados:
        timeout (float): Tempo máximo de espera por resposta de um host ou porta,
                         em segundos.

        threads (int): Quantidade de threads utilizadas para execução paralela
                       das tarefas de scan.

        delay (float): Intervalo de tempo (em segundos) aplicado entre cada probe
                       enviado durante o scan, utilizado para controle de taxa
                       e redução de carga na rede.

    Essa configuração é aplicada globalmente aos módulos de varredura,
    garantindo consistência de comportamento entre diferentes tipos de scan
    (ex.: Host Discovery, Port Scanning, Service Detection).

    Exemplo de uso:

        config = ScanConfig(timeout=0.5, threads=200, delay=0.01)
        config.print_config()

    Saída esperada:

        [CONFIG]
        Threads: 200
        Timeout: 0.5s
        Delay: 0.01s
    """

    def __init__(self, timeout=1.0, threads=100, delay=0):
        self.timeout = timeout
        self.threads = threads
        self.delay = delay

    def print_config(self):
        """
        Exibe no console a configuração atual de performance do scanner.

        Utilizado principalmente para registrar os parâmetros aplicados antes
        do início da execução de um scan.
        """
        print("[CONFIG]")
        print(f"Threads: {self.threads}")
        print(f"Timeout: {self.timeout}s")
        print(f"Delay: {self.delay}s\n")
