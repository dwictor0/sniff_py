class ScanConfig:
    """
    Classe responsável por armazenar e gerenciar os parâmetros de
    performance utilizados durante a execução do scanner.

    Esses parâmetros influenciam diretamente no comportamento do scan,
    como tempo de espera por respostas, nível de paralelismo e intervalo
    entre probes enviados.
    """

    def __init__(self, timeout: float = 1.0, threads: int = 100, delay: float = 0.0):
        self.timeout = timeout
        self.threads = threads
        self.delay = delay

    def print_config(self):
        """
        Exibe no console a configuração atual de performance do scanner.
        """
        print("[CONFIG]")
        print(f"{'Threads':<10}: {self.threads:<8}")
        print(f"{'Timeout':<10}: {self.timeout:<8.2f}s")
        print(f"{'Delay':<10}: {self.delay:<8.2f}s\n")

    def to_dict(self):
        """
        Retorna a configuração em formato de dicionário.
        """
        return {
            "timeout": self.timeout,
            "threads": self.threads,
            "delay": self.delay,
        }
