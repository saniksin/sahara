import asyncio
from functools import wraps

from sqlalchemy.ext.asyncio import AsyncSession

from db_api.database import Accounts, db
from data.session import BaseAsyncSession
from data.config import logger
from settings.settings import NUMBER_OF_ATTEMPTS
from data.session import BaseAsyncSession


class Base:
    def __init__(self, data: Accounts, async_session: BaseAsyncSession | None = None):

        self.data = data

        if async_session:
            self.async_session = async_session
        else:
            self.async_session = BaseAsyncSession(
                proxy=data.proxy, 
                verify=False, 
                user_agent=self.data.user_agent
            )

        self.version = self.data.user_agent.split('Chrome/')[1].split('.')[0]
        self.platform = self.data.user_agent.split(' ')[1][1:].replace(';', '')
        if self.platform == "Macintosh":
            self.platform = "MacOS"
        elif self.platform == "X11":
            self.platform = "Linux"


    @staticmethod
    def retry(func):
        @wraps(func)
        async def wrapper(self, *args, **kwargs):
            for num in range(1, NUMBER_OF_ATTEMPTS + 1):
                try:
                    logger.info(f'[{self.data.id}] | {self.data.evm_address} | попытка {num}/{NUMBER_OF_ATTEMPTS}')
                    # Попробовать вызвать оригинальную функцию
                    status = await func(self, *args, **kwargs)
                    if status:
                        return True
                    else:
                        continue 
                
                except Exception as e:
                    # Если ошибка не из 'Locked', повторяем попытку
                    logger.error(f"[{self.data.id}] | {self.data.evm_address} | Attempt {num}/{NUMBER_OF_ATTEMPTS} failed due to: {e}")
                    if num == NUMBER_OF_ATTEMPTS:
                        return  
                    await asyncio.sleep(1)  

        return wrapper


    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.async_session.close()

    async def write_to_db(self):
        async with AsyncSession(db.engine) as session:
            await session.merge(self.data)
            await session.commit()
