import os
import ast

from dotenv import load_dotenv
from data.config import logger
from distutils.util import strtobool

load_dotenv()

try:
    # КОЛ-ВО ПОПЫТОК
    NUMBER_OF_ATTEMPTS: int = int(os.getenv('NUMBER_OF_ATTEMPTS'))

    # Одновременное кол-во асинхронных задач
    ASYNC_TASK_IN_SAME_TIME: int = int(os.getenv('ASYNC_TASK_IN_SAME_TIME'))
    
    USE_PRIVATE_KEYS_ENCRYPTION: bool = bool(strtobool(os.getenv('USE_PRIVATE_KEYS_ENCRYPTION')))

    # ADD_TWITTER
    ADD_TWITTER: bool = bool(strtobool(os.getenv('ADD_TWITTER')))
    ADD_DISCORD: bool = bool(strtobool(os.getenv('ADD_DISCORD')))

    # ключи от сервисов капчи
    SERVICE_TO_USE: str = str(os.getenv('SERVICE_TO_USE'))
    HCAPTCHA_SERVICE_TO_USE: str = str(os.getenv('HCAPTCHA_SERVICE_TO_USE'))
    API_KEY_CAPMONSTER: str = str(os.getenv('API_KEY_CAPMONSTER'))
    API_KEY_CAPSOLVER: str = str(os.getenv('API_KEY_CAPSOLVER'))
    API_KEY_24_CAPTCHA: str = str(os.getenv('API_KEY_24_CAPTCHA'))
    API_KEY_BESTCAPTCHA: str = str(os.getenv('API_KEY_BESTCAPTCHA'))


    # SAHARA реф код
    SAHARA_REF_CODE: str = str(os.getenv('SAHARA_REF_CODE'))

    # SLEEP BEETWEEN ACTION
    SLEEP_FROM: int = int(os.getenv('SLEEP_FROM'))
    SLEEP_TO: int = int(os.getenv('SLEEP_TO'))
    SLEEP_BEETWEEN_ACTIONS: list = [SLEEP_FROM, SLEEP_TO]
    
    # Рефка 
    USE_REF_LINK: str = bool(strtobool(os.getenv('USE_REF_LINK')))
    REF_LINK: str = str(os.getenv('REF_LINK'))

    DISCORD_SITE_KEY = 'a9b5fb07-92ff-493f-86fe-352a2803b3df'
    SAHARA_FAUCET_SITE_KEY = '94998d34-914f-4b97-8510-b3dc0d8e4aef'

    DISCORD_INVITE = str(os.getenv('DISCORD_INVITE'))

    ACCOUNT_SHUFFLE: bool = bool(strtobool(os.getenv('ACCOUNT_SHUFFLE')))

    PERCENT_NATIVE_TO_TX = os.getenv('PERCENT_NATIVE_TO_TX')
    if PERCENT_NATIVE_TO_TX:
        PERCENT_NATIVE_TO_TX = ast.literal_eval(PERCENT_NATIVE_TO_TX) 
    MIN_BALANCE = float(os.getenv('MIN_BALANCE'))

except TypeError:
    logger.warning('Вы не создали .env и не добавили туда настройки')