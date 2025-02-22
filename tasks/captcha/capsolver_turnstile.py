import traceback
import asyncio

from data.session import BaseAsyncSession
from data.config import logger
from settings.settings import API_KEY_CAPSOLVER, NUMBER_OF_ATTEMPTS
from db_api.models import Accounts


class CapsolverTurnstile:
    def __init__(self, data: Accounts, async_session: BaseAsyncSession):
        self.data: Accounts = data
        self.async_session: BaseAsyncSession = async_session

    async def wait_for_turnstile_captcha(self):
        """Ожидание решения Cloudflare Turnstile через Capsolver."""
        for num, _ in enumerate(range(NUMBER_OF_ATTEMPTS), start=1):
            try:
                status, task_id = await self.create_task()
                if status:
                    logger.info(f'[{self.data.id}] | {self.data.evm_address} | успешно создал задачу: {task_id}')
                    status, answer = await self.check_capsolver_task_complete(task_id)
                    if status:
                        logger.info(f'[{self.data.id}] | {self.data.evm_address} | успешно получил решение: {task_id}')
                        return answer
                else:
                    logger.warning(f'[{self.data.id}] | {self.data.evm_address} | не удалось создать задачу.')
                    continue

            except Exception as error:
                logger.error(f'[{self.data.id}] | {self.data.evm_address} | ошибка: {error}')
                print(traceback.print_exc())
                continue
        return False

    async def create_task(self):
        """Создание задачи для решения Cloudflare Turnstile через Capsolver."""
        url = "https://api.capsolver.com/createTask"

        json_data = {
            "clientKey": API_KEY_CAPSOLVER,
            "task": {
                "type": "AntiTurnstileTaskProxyLess",
                "websiteURL": "https://faucet.saharalabs.ai/",
                "websiteKey": "0x4AAAAAAA8hNPuIp1dAT_d9"
            }
        }

        response = await self.async_session.post(url=url, json=json_data)
        if response.status_code == 200:
            answer = response.json()
            if "taskId" in answer:
                return True, answer["taskId"]

        logger.warning(f'[{self.data.id}] | {self.data.evm_address} | не удалось создать задачу. Ответ: {response.status_code}')
        return False, 'Ошибка при создании задачи'

    async def check_capsolver_task_complete(self, task_id):
        """Проверка готовности решения капчи в Capsolver."""
        url = "https://api.capsolver.com/getTaskResult"
        attempts = 0

        while attempts < 300:
            json_data = {
                "clientKey": API_KEY_CAPSOLVER,
                "taskId": task_id
            }

            response = await self.async_session.post(url=url, json=json_data)
            answer = response.json()

            if answer.get("status") == "processing":
                attempts += 1
                await asyncio.sleep(1)
                continue

            if answer.get("status") == "ready":
                return True, answer["solution"]["token"]

            if answer.get("errorId", 0) != 0:
                msg = f'[{self.data.id}] | {self.data.evm_address} | ошибка при решении капчи: {answer.get("errorDescription", "Неизвестная ошибка")} '
                logger.warning(msg)
                return False, answer.get("errorDescription", "Unknown error")

            msg = f'[{self.data.id}] | {self.data.evm_address} | неизвестная ошибка при решении капчи. Ответ: {answer}'
            logger.warning(msg)
            return False, 'Unknown error'

        return False, 'Не удалось получить решение'