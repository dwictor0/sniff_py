class ScanConfig:
    """
    Classe responsável por armazenar e gerenciar os parâmetros de
    performance utilizados durante a execução do scanner.

    Esses parâmetros influenciam diretamente no comportamento do scan,
    como tempo de espera por respostas, nível de paralelismo e intervalo
    entre probes enviados.

    Attributes:
        timeout (float): Tempo máximo de espera por resposta de cada
            operação de rede (em segundos).

        threads (int): Número de threads utilizadas para executar
            operações de scan em paralelo.

        delay (float): Intervalo de tempo (em segundos) entre cada
            probe enviado pelo scanner, usado para controle de carga
            e ajuste de performance.
    """

    def __init__(self, timeout: float = 1.0, threads: int = 100, delay: float = 0.0):
        """
        Inicializa a configuração global do scanner.

        Args:
            timeout (float): Tempo limite para respostas de rede.
            threads (int): Quantidade de threads usadas na execução paralela.
            delay (float): Tempo de espera entre probes enviados.
        """
        self.timeout = timeout
        self.threads = threads
        self.delay = delay

    def print_config(self):
        """
        Exibe no console a configuração atual de performance do scanner.

        Essa função é normalmente chamada antes do início do scan para
        registrar os parâmetros utilizados na execução.
        """
        print("[CONFIG]")
        print(f"Threads: {self.threads}")
        print(f"Timeout: {self.timeout}s")
        print(f"Delay: {self.delay}s\n")

    def to_dict(self):
        """
        Retorna a configuração em formato de dicionário.

        Útil para integração com outros módulos do sistema.
        """
        return {
            "timeout": self.timeout,
            "threads": self.threads,
            "delay": self.delay,
        }
