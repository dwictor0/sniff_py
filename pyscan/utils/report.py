def print_console(results):
    print(f"{'PORT':<7} {'STATE':<8} {'SERVICE':<12} {'VERSION'}")
    for r in results.results:
        print(
            f"{r.port}/tcp  {r.state:<8} {r.service or 'Unknown':<12} {r.version or 'Unknown'}"
        )
    print(
        f"\nScanned {results.host} in {results.duration:.2f}s. Open ports: {results.open_ports}"
    )
