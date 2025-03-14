import os
import r2pipe
import argparse
import csv
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# Функция для загрузки описаний функций из CSV-файла
def load_function_descriptions(file_path):
    descriptions = {}
    with open(file_path, 'r', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        for row in reader:
            func_name = row['Function']
            descriptions[func_name] = row['Description']
    return descriptions

# Функция для выполнения команд radare2 с использованием r2pipe
def analyze_file(file_path, commands, log_dir, function_descriptions, missing_descriptions):
    try:
        # Открываем файл в radare2
        r2 = r2pipe.open(file_path)

        # Создаем HTML-файл для текущего файла
        html_file_name = os.path.join(log_dir, f"{os.path.splitext(file_path)[0]}.html")
        with open(html_file_name, 'w', encoding='utf-8') as html_file:
            # Начало HTML-документа
            html_file.write("<!DOCTYPE html>\n<html>\n<head>\n")
            html_file.write(f"<title>Analysis Results for {file_path}</title>\n")
            html_file.write("<style>\n")
            html_file.write("body { font-family: Arial, sans-serif; }\n")
            html_file.write("a { color: #1a73e8; text-decoration: none; }\n")
            html_file.write("a:hover { text-decoration: underline; }\n")
            html_file.write("pre { background: #f4f4f4; padding: 10px; border-radius: 5px; }\n")
            html_file.write("table { border-collapse: collapse; width: 100%; }\n")
            html_file.write("th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n")
            html_file.write("th { background-color: #f2f2f2; }\n")
            html_file.write("</style>\n")
            html_file.write("</head>\n<body>\n")
            html_file.write(f"<h1>Analysis Results for {file_path}</h1>\n")
            html_file.write("<h2>Commands:</h2>\n<ul>\n")
            for command in commands:
                html_file.write(f'<li><a href="#{file_path}_{command.replace(" ", "_")}">{command}</a></li>\n')
            html_file.write("</ul>\n")
            html_file.write("<h2>Results:</h2>\n")

            # Выполняем команды и записываем результаты
            for command in commands:
                try:
                    # Выполняем команду
                    output = r2.cmd(command)
                    # Записываем результат в HTML
                    html_file.write(f'<h3 id="{file_path}_{command.replace(" ", "_")}">Command: {command}</h3>\n')

                    # Если команда - ii, форматируем вывод в таблицу
                    if command == "ii":
                        html_file.write("<h4>Imports:</h4>\n")
                        html_file.write("<table border='1'>\n")
                        html_file.write("<tr><th>nth</th><th>vaddr</th><th>bind</th><th>type</th><th>lib</th><th>name</th><th>Description</th></tr>\n")

                        # Разбиваем вывод на строки и пропускаем первую строку (заголовок)
                        lines = output.splitlines()
                        for line in lines[1:]:  # Пропускаем первую строку
                            # Парсим строку, разделенную пробелами
                            parts = line.split()
                            if len(parts) >= 6:
                                nth = parts[0]
                                vaddr = parts[1]
                                bind = parts[2]
                                type_ = parts[3]
                                lib = parts[4]
                                name = parts[5]

                                # Получаем описание функции из словаря
                                description = function_descriptions.get(name, "No description available")

                                # Если описание отсутствует, добавляем запись в missing_descriptions
                                if description == "No description available":
                                    missing_descriptions.append((lib, name))

                                # Добавляем строку в таблицу
                                html_file.write(f"<tr><td>{nth}</td><td>{vaddr}</td><td>{bind}</td><td>{type_}</td><td>{lib}</td><td>{name}</td><td>{description}</td></tr>\n")

                        html_file.write("</table>\n")

                    # Если команда начинается с izz и вывод не пустой, форматируем вывод в таблицу
                    elif command.startswith("izz") and output.strip():
                        html_file.write("<h4>Strings:</h4>\n")
                        html_file.write("<table border='1'>\n")
                        html_file.write("<tr><th>Один</th><th>Два</th><th>Адрес</th><th>Четыре</th><th>Пять</th><th>Тип</th><th>Кодировка</th><th>Значение</th></tr>\n")

                        # Разбиваем вывод на строки
                        lines = output.splitlines()
                        for line in lines:
                            # Парсим строку, разделенную пробелами
                            parts = line.split()
                            if len(parts) >= 8:
                                one = parts[0]
                                two = parts[1]
                                address = parts[2]
                                four = parts[3]
                                five = parts[4]
                                type_ = parts[5]
                                encoding = parts[6]
                                value = " ".join(parts[7:])  # Значение может содержать пробелы

                                # Добавляем строку в таблицу
                                html_file.write(f"<tr><td>{one}</td><td>{two}</td><td>{address}</td><td>{four}</td><td>{five}</td><td>{type_}</td><td>{encoding}</td><td>{value}</td></tr>\n")

                        html_file.write("</table>\n")

                    # Если команда - iE и вывод не пустой, форматируем вывод в таблицу
                    elif command == "iE" and output.strip():
                        html_file.write("<h4>Exports:</h4>\n")
                        html_file.write("<table border='1'>\n")
                        html_file.write("<tr><th>nth</th><th>paddr</th><th>vaddr</th><th>bind</th><th>type</th><th>size</th><th>lib</th><th>name</th><th>demangled</th></tr>\n")

                        # Разбиваем вывод на строки и пропускаем первую строку (заголовок)
                        lines = output.splitlines()
                        for line in lines[1:]:  # Пропускаем первую строку
                            # Парсим строку, разделенную пробелами
                            parts = line.split()
                            if len(parts) >= 9:
                                nth = parts[0]
                                paddr = parts[1]
                                vaddr = parts[2]
                                bind = parts[3]
                                type_ = parts[4]
                                size = parts[5]
                                lib = parts[6]
                                name = parts[7]
                                demangled = " ".join(parts[8:])  # Demangled может содержать пробелы

                                # Добавляем строку в таблицу
                                html_file.write(f"<tr><td>{nth}</td><td>{paddr}</td><td>{vaddr}</td><td>{bind}</td><td>{type_}</td><td>{size}</td><td>{lib}</td><td>{name}</td><td>{demangled}</td></tr>\n")

                        html_file.write("</table>\n")

                    else:
                        # Для других команд выводим как есть
                        html_file.write(f"<pre>{output}</pre>\n")

                    # Сбрасываем буфер, чтобы данные сразу записывались в файл
                    html_file.flush()
                except Exception as e:
                    html_file.write(f"<p style='color: red;'>Error executing command '{command}' for {file_path}: {e}</p>\n")
                    html_file.flush()

            # Конец HTML-документа
            html_file.write("</body>\n</html>")

        print(f"Results for {file_path} saved to {html_file_name}")
    except Exception as e:
        print(f"Error analyzing {file_path}: {e}")
    finally:
        # Закрываем соединение с radare2
        r2.quit()

# Основная функция для обработки файлов
def process_files(files_to_analyze, commands, log_dir, max_workers, function_descriptions):
    missing_descriptions = []  # Список для хранения записей с отсутствующими описаниями
    total_files = len(files_to_analyze)  # Общее количество файлов
    processed_files = 0  # Счетчик обработанных файлов

    # Начало отсчета времени
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(analyze_file, file, commands, log_dir, function_descriptions, missing_descriptions): file for file in files_to_analyze}
        for future in as_completed(futures):
            file = futures[future]
            try:
                future.result()  # Ожидаем завершения задачи
                processed_files += 1
                print(f"Processed {processed_files}/{total_files} files: {file}")
            except Exception as e:
                print(f"Error processing {file}: {e}")

    # Сохраняем записи с отсутствующими описаниями в CSV-файл
    if missing_descriptions:
        missing_csv_path = os.path.join(log_dir, "missing_descriptions.csv")
        with open(missing_csv_path, 'w', encoding='utf-8', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["Library", "Function"])  # Заголовки столбцов
            writer.writerows(missing_descriptions)  # Записи
        print(f"Missing descriptions saved to {missing_csv_path}")

    # Затраченное время
    elapsed_time = time.time() - start_time
    print(f"Processing completed. Total files processed: {processed_files}/{total_files}")
    print(f"Time elapsed: {elapsed_time:.2f} seconds")

# Создаем папку log_dis, если её нет
log_dir = "log_dis"
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# Парсинг аргументов командной строки
parser = argparse.ArgumentParser(description="Analyze .exe and .dll files using radare2.")
parser.add_argument("-c", "--concurrency", type=int, default=5, help="Number of files to process simultaneously (max 50).")
parser.add_argument("-f", "--file", type=str, default="kom.txt", help="Path to the file containing radare2 commands.")
parser.add_argument("--func", type=str, default="func.csv", help="Path to the CSV file containing function descriptions.")
args = parser.parse_args()

# Проверка значения concurrency
if args.concurrency < 1 or args.concurrency > 50:
    print("Error: Concurrency value must be between 1 and 50.")
    exit(1)

# Проверка существования файла команд
if not os.path.exists(args.file):
    print(f"Error: Command file '{args.file}' not found.")
    exit(1)

# Проверка существования файла с описаниями функций
if not os.path.exists(args.func):
    print(f"Error: Function descriptions file '{args.func}' not found.")
    exit(1)

# Чтение команд из файла
with open(args.file, 'r') as file:
    commands = [line.strip() for line in file if line.strip()]

# Загрузка описаний функций
function_descriptions = load_function_descriptions(args.func)

# Поиск всех .exe и .dll файлов в текущей папке
files_to_analyze = [f for f in os.listdir() if f.endswith('.exe') or f.endswith('.dll')]

# Анализ файлов с использованием многопоточности
process_files(files_to_analyze, commands, log_dir, args.concurrency, function_descriptions)

print("Analysis complete. Results saved to individual HTML files in the 'log_dis' folder.")
