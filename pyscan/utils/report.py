def print_console(result):
    for r in result.results:
        print(f"{r.port}/{r.protocol}   {r.state}")

    print("\n[INFO] Port scan finalizado.")
    print(f"Portas abertas: {result.open_ports}")
    print(f"Duração: {result.duration:.2f}s")
