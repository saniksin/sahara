import os
import sys
import asyncio
from pathlib import Path

from loguru import logger


# Определяем путь и устанавливаем root dir
if getattr(sys, 'frozen', False):
    ROOT_DIR = Path(sys.executable).parent.absolute()
else:
    ROOT_DIR = Path(__file__).parent.parent.absolute()


# Папка status
STATUS_DIR = os.path.join(ROOT_DIR, 'status')
LOG = os.path.join(STATUS_DIR, 'log.txt')
ACCOUNTS_DB = os.path.join(STATUS_DIR, 'accounts.db')
SALT_PATH = os.path.join(STATUS_DIR, 'salt.dat')

# Импорт
IMPORT_DIR = os.path.join(ROOT_DIR, 'import')
EVM_PKS = os.path.join(IMPORT_DIR, 'evm_pks.txt')
PROXIES = os.path.join(IMPORT_DIR, 'proxies.txt')
EMAIL_DATA = os.path.join(IMPORT_DIR, 'emails.txt')
TWITTER_TOKENS = os.path.join(IMPORT_DIR, 'twitter_tokens.txt')
DISCORD_TOKENS = os.path.join(IMPORT_DIR, 'discord_tokens.txt')
DISCORD_PROXYS = os.path.join(IMPORT_DIR, 'discord_proxys.txt')

# STATUS DISCORD INVITE
DISCORD_TOKEN_SUCCESS = os.path.join(STATUS_DIR, 'discord_success_join.txt')
DISCORD_TOKEN_FAILS = os.path.join(STATUS_DIR, 'discord_failed_join.txt')

# Создаем
IMPORTANT_FILES = [EVM_PKS, PROXIES, EMAIL_DATA, TWITTER_TOKENS, DISCORD_TOKENS, DISCORD_PROXYS, DISCORD_TOKEN_SUCCESS, DISCORD_TOKEN_FAILS]

# Кол-во выполненных асинхронных задач, блокировщий задач asyncio
completed_tasks = [0]
remaining_tasks = [0]
tasks_lock = asyncio.Lock()

CIPHER_SUITE = []

# Логер
logger.add(LOG, format='{time:YYYY-MM-DD HH:mm:ss} | {level} | {message}', level='DEBUG')
