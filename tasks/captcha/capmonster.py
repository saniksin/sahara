import traceback
import asyncio


from data.session import BaseAsyncSession
from data.config import logger
from settings.settings import API_KEY_CAPMONSTER, NUMBER_OF_ATTEMPTS
from db_api.models import Accounts


class Capmonster:

    def __init__(self, data: Accounts, async_session: BaseAsyncSession):
        self.data: Accounts = data
        self.async_session: BaseAsyncSession = async_session

    async def wait_for_geetest_gcaptcha(self):
        for num, _ in enumerate(range(NUMBER_OF_ATTEMPTS), start=1):
            try:
                status, task_id = await self.create_task()
                if status:
                    logger.info(f'[{self.data.id}] | {self.data.evm_address} | успешно создал задачу: {task_id}')
                    status, answer = await self.check_capmonster_task_complete(task_id)
                    if status:
                        logger.info(f'[{self.data.id}] | {self.data.evm_address} | успешно получил решение задачи: {task_id}')
                        return answer
                    else:
                        continue
                else:
                    continue

            except Exception as error:
                logger.error(f'[{self.data.id}] | {self.data.evm_address} | неизвестная ошибка: {error}')
                print(traceback.print_exc())
                continue
        return False

    async def create_task(self):

        url = 'https://api.capmonster.cloud/createTask'

        json_data = {
            "clientKey": API_KEY_CAPMONSTER,
            "task": {
            "type": "GeeTestTaskProxyless",
            "websiteURL": "https://galxe.com/accountSetting?tab=SocialLinlk",
            "gt": "244bcb8b9846215df5af4c624a750db4",
            "version": 4,
            "userAgent": self.data.user_agent
            }
        }

        response = await self.async_session.post(url=url, json=json_data)

        if response.status_code == 200:
            answer = response.json()
            try:
                return True, answer['taskId']
            except KeyError:
                pass
        logger.warning(f'[{self.data.id}] | {self.data.evm_address} | не удалось создать задачу. Ответ сервера: {response.status_code}')
        return False, 'problem with task create'

    async def check_capmonster_task_complete(self, task_id):
        i = 0
        while i < 300:
            json_data = {
                "clientKey": API_KEY_CAPMONSTER,
                "taskId": task_id
            }

            response = await self.async_session.post('https://api.capmonster.cloud/getTaskResult', json=json_data)

            answer = response.json()
            try:
                if answer.get('status', False) == 'processing':
                    i += 1
                    await asyncio.sleep(1)
                    continue

                elif answer.get('status', False) == 'ready':
                    return True, answer['solution']

                elif answer.get('status', False) != 0:
                    msg = f'[{self.data.id}] | {self.data.evm_address} | произошла ошибка при решение капчи. {answer["errorDescription"]}'
                    logger.warning(msg)
                    return False, answer['errorDescription']

                else:
                    msg = f'[{self.data.id}] | {self.data.evm_address} | неизвестная ошибка при решение капчи. Ответ сервера: {answer})'
                    logger.warning(msg)
                    return False, 'uknown error'
            except KeyError:
                print(response.text)
                i += 1
                await asyncio.sleep(1)
                continue

        return False, 'Not possible receive solution'