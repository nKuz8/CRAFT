import random


def main():
    with open("ot_1mb.txt", "w") as file:
        random.random()
        for i in range(2 ** 20):
            file.write(chr(random.randint(65, 123)))
    with open("ot_100mb.txt", "w") as file:
        random.random()
        for i in range(104857600):
            file.write(chr(random.randint(65, 123)))
    with open("ot_1Gb.txt", "w") as file:
        random.random()
        for i in range(2 ** 30):
            file.write(chr(random.randint(65, 123)))


if __name__ == "__main__":
    main()
