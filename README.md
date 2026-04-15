# pythonctript

Краткий мануал по запуску `multi-scanner-results_6.py`.

## Что делает скрипт
Скрипт объединяет результаты из 4 источников:
- SonarQube (`.xlsx`)
- Semgrep (`.sarif`)
- Gitleaks (`.json`)
- Trufflehog (`.json`)

Дальше он:
1. Нормализует поля в единую таблицу.
2. Удаляет дубли.
3. Пытается перевести описания по `translations.json`.
4. Сохраняет итог в `results.xlsx` и форматирует Excel.

## Зависимости
```bash
pip install pandas openpyxl
```

## Быстрый запуск
Если файлы названы по умолчанию и лежат рядом со скриптом:
```bash
python multi-scanner-results_6.py
```

## Запуск со своими путями
```bash
python multi-scanner-results_6.py \
  --sonarqube ./input/sonarqube.xlsx \
  --semgrep ./input/semgrep.sarif \
  --gitleaks ./input/gitleaks.json \
  --trufflehog ./input/trufflehog.json \
  --translations-json ./translations.json \
  --output ./results.xlsx
```

## Что важно по входным данным
- **SonarQube**: берётся лист `Issues` и фильтруется `Type = VULNERABILITY`.
- **Semgrep**: берутся `description`, `file`, `startLine`, `snippet`.
- **Gitleaks**: используется `Match`.
- **Trufflehog**: используется `Redacted`.

## Если что-то пошло не так
- Проверь, что файлы реально существуют по переданным путям.
- Проверь кодировку и валидность JSON/SARIF.
- Если `translations.json` отсутствует — скрипт создаст/обновит его в процессе.

---

Если хочешь, могу дальше сделать:
- мини-проверку входных файлов перед запуском;
- более понятные сообщения об ошибках;
- шаблон структуры папок (`input/`, `output/`) для команды.
