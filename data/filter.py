import sys

if __name__ == "__main__":
    plaintext_length = 0

    try:
        plaintext_length = int(sys.argv[1])
    except Exception:
        print("Usage: python filter.py <PLAINTEXT_LENGTH>")
        sys.exit(1)

    with open("passwords.txt", "r") as file:
        for line in file:
            line = line.strip()
            if len(line) == plaintext_length:
                print(line)
