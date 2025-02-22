# Galxe + SaharaAI

Cофт для автоматизации задач **Galxe + SaharaAI**.

## 🎥 Видеообзор настройки и работы
[тык](https://youtu.be/qYgi4YacC_E)

## 📢 Контакты

- Мой Telegram канал: [@cryptosaniksin](https://t.me/cryptosaniksin)
- Чат: [@cryptosaniksin_chat](https://t.me/cryptosaniksin_chat)

## 📦 Модули

- **Sahara** 
- **Galxe** (необязательно)
- **Discord** (необязательно)

## 🐍 Требования

- Python 3.12

## ⚙️ Установка

```sh
# Клонируем репозиторий
git clone https://github.com/saniksin/sahara
cd sahara

# Устанавливаем зависимости
pip install -r requirements.txt
```

## 🔧 Конфигурация

```sh
# Создаём .env-файл на основе примера
cp .env_example .env
```
- Заполните `.env` своими конфигурационными данными.
- Запустите проект для создания недостающих файлов:

```sh
python main.py
```

## 📂 Настройка файлов

Поместите необходимые файлы в папку `import`:
- **emails.txt** (необязательно): `email@example.com:password`
- **discord_tokens.txt** (необязательно): список токенов Discord.
- **twitter_tokens.txt** (необязательно): список auth-токенов Twitter.
- **proxies.txt** (**обязательно**): `http://login:password@ip:port`
- **evm_pks.txt** (**обязательно**): приватные ключи Ethereum.
  - Для зашифрованных ключей добавьте **файл с солью** в папку `status`.
  - Зашифровать ключи можно с помощью [Crypto-Mate](https://github.com/saniksin/crypto-mate).

## 🚀 Использование

```sh
python main.py
```

