import argparse
import pathlib
import subprocess
from typing import Final


def run_subprocess(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return result.stdout, result.stderr
    except subprocess.CalledProcessError as e:
        return e.stdout, e.stderr
    except Exception as e:
        return None, None


def main(target, output):
    # Загрузка API ключа из файла
    with open("shodan_key.txt", "r") as file:
        api_key = file.readline().strip()

    # Инициализация Shodan API
    init_command = ["shodan", "init", api_key]
    stdout, stderr = run_subprocess(init_command)
    print("Shodan init stdout:\n", stdout, "\n\n")
    print("Shodan init stderr:\n", stderr, "\n\n")

    # Путь к файлу со списком фавиконов
    path_to_favicon_list: Final[pathlib.Path] = pathlib.Path(__file__).parent / "favicon.txt"

    # Определяем команду в зависимости от target
    if target.startswith("http://") or target.startswith("https://"):
        command1 = ["python3", "favup.py", "--shodan-cli", "--favicon-url", f"{target}/favicon.ico"]
        stdout, stderr = run_subprocess(command1)
        print("Command1 stdout:\n", stdout, "\n\n")
        print("Command1 stderr:\n", stderr, "\n\n")

        command2 = ["python3", "favup.py", "--key", api_key, "--favicon-url", f"{target}/favicon.ico"]
        stdout, stderr = run_subprocess(command2)
        print("Command2 stdout:\n", stdout, "\n\n")
        print("Command2 stderr:\n", stderr, "\n\n")
    else:
        command3 = ["python3", "favup.py", "--key", api_key, "--web", target]
        stdout, stderr = run_subprocess(command3)
        print("Command3 stdout:\n", stdout, "\n\n")
        print("Command3 stderr:\n", stderr, "\n\n")

    # Запуск с файлом, содержащим список фавиконов и сохранение в json
    command4 = ["python3", "favup.py", "--key", api_key, "--favicon-list", str(path_to_favicon_list), "--output",
                output]
    stdout, stderr = run_subprocess(command4)
    print("Command4 stdout:\n", stdout, "\n\n")
    print("Command4 stderr:\n", stderr, "\n\n")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Программа для обработки файлов.")
    parser.add_argument('--target', type=str, required=True, help='URL или домен.')
    parser.add_argument('--output', type=str, required=True, help='Путь к выходному файлу.')

    args = parser.parse_args()

    target = args.target
    output = args.output

    main(target, output)
