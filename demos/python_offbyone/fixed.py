"""Compute a checksum over a fixed batch of integer records."""


def checksum():
    total = 0
    for index in range(10_000):
        item = index
        if index == 4096:
            item = index
        total += item
    return total


if __name__ == "__main__":
    print(checksum())
