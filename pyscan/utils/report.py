def print_console(results):
    print(f"{'PORT':<8}{'STATE':<10}{'SERVICE':<15}{'VERSION':<20}")

    for r in results.results:
        print(
            f"{f'{r.port}/tcp':<8}"
            f"{r.state:<10}"
            f"{(r.service or 'Unknown'):<15}"
            f"{(r.version or 'Unknown'):<20}"
        )

    print(
        f"\nScanned {results.host} "
        f"in {results.duration:.2f}s. "
        f"Open ports: {results.open_ports}"
    )
