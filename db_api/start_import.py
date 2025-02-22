import sys
import random
import traceback

from fake_useragent import UserAgent
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError

from db_api.database import get_account, db
from db_api.models import Accounts
from clients.eth.eth_client import EthClient
from data.config import logger
from utils.encrypt_params import get_private_key


class ImportToDB:
    imported = []
    edited = []

    @staticmethod
    async def add_info_to_db(accounts_data: list[dict]) -> None:
        """
        Добавляет или обновляет информацию об аккаунтах в базе данных.
        :param accounts_data: список словарей с полями 'evm_pk', 'proxy', ...
        """
        async with AsyncSession(db.engine) as session:
            if not accounts_data:
                logger.info('There are no wallets in the file!')
                return

            total = len(accounts_data)
            logger.info(f'Начинаем импорт {total} аккаунтов')

            for num, account in enumerate(accounts_data, start=1):
                logger.info(f'Импортирую аккаунт {num} из {total}')
                try:
                    evm_pk = account['evm_pk']
                    proxy = account['proxy']
                    email = account['email']
                    twitter_token = account['twitter_token']
                    discord_token = account['discord_token']

                    user_agent = UserAgent().chrome
                    if 'iPhone' in user_agent or 'iPad' in user_agent:
                        while True:
                            user_agent = UserAgent().chrome
                            if 'iPhone' not in user_agent and 'iPad' not in user_agent:
                                break
                    
                    check_if_key_correct = get_private_key(account, create_db=True)
                    if 'wrong password or salt!' in check_if_key_correct:
                        logger.error(f'{check_if_key_correct}. Key: {evm_pk}. CHECK PASSWORD OR SALT!!!')
                        sys.exit(1)

                    # Если есть EVM-приватник, получаем EVM-адрес
                    if evm_pk:
                        evm_client = EthClient(
                            private_key=check_if_key_correct,
                            proxy=proxy,
                            user_agent=user_agent
                        )
                        evm_address = evm_client.account.address
                    else:
                        evm_address = ''

                    # Проверяем, есть ли уже запись в БД
                    account_instance = await get_account(evm_pk=evm_pk)

                    if account_instance:
                        # Обновляем, если есть изменения
                        await ImportToDB.update_account_instance(
                            session,
                            account_instance,
                            evm_address,
                            proxy,
                            email,
                            twitter_token,
                            discord_token,
                            user_agent
                        )
                    else:
                        # Создаём новую запись
                        account_instance = Accounts(
                            evm_pk=evm_pk,
                            evm_address=evm_address,
                            proxy=proxy,
                            email=email,
                            twitter_token=twitter_token,
                            discord_token=discord_token,
                            user_agent=user_agent
                        )
                        ImportToDB.imported.append(account_instance)
                        session.add(account_instance)

                except Exception as err:
                    logger.error(f'Ошибка при обработке аккаунта №{num}: {err}')
                    logger.exception('Stack Trace:')

            # Формируем текстовый отчёт
            report_lines = []

            if ImportToDB.imported:
                report_lines.append("\n--- Imported")
                report_lines.append("{:<4}{:<45}".format("N", "EVM Address"))
                for i, wallet in enumerate(ImportToDB.imported, 1):
                    report_lines.append(
                        "{:<4}{:<45}".format(
                            i,
                            wallet.evm_address or "-"
                        )
                    )

            if ImportToDB.edited:
                report_lines.append("\n--- Edited")
                report_lines.append("{:<4}{:<45}".format("N", "EVM Address"))
                for i, wallet in enumerate(ImportToDB.edited, 1):
                    report_lines.append(
                        "{:<4}{:<45}".format(
                            i,
                            wallet.evm_address or "-"
                        )
                    )

            # Логируем и выводим финальную информацию
            if report_lines:
                full_report = "\n".join(report_lines)
                logger.info(full_report)  # Выводим в лог
                #print(full_report)        # Дублируем в консоль

            logger.info(
                f"Импорт завершён! "
                f"Импортировано: {len(ImportToDB.imported)} из {total}. "
                f"Обновлено: {len(ImportToDB.edited)} из {total}."
            )
            print(
                f"Done! {len(ImportToDB.imported)}/{total} wallets were imported, "
                f"and {len(ImportToDB.edited)}/{total} wallets were updated."
            )

            try:
                await session.commit()
            except IntegrityError as e:
                await session.rollback() 
                if "UNIQUE constraint failed" in str(e.orig):
                    print(f"Ошибка: Дублирующая запись. Данные не добавлены: {e}")
                    return
                else:
                    print(f"Неожиданная ошибка: {e}")
                    return


    @staticmethod
    async def update_account_instance(
        session: AsyncSession,
        account_instance: Accounts,
        evm_address: str,
        proxy: str,
        email: str,
        twitter_token: str,
        discord_token: str,
        user_agent: str
    ) -> None:
        """
        Обновляет поля account_instance, если они отличаются от текущих.

        :param session: активная сессия SQLAlchemy
        :param account_instance: модель аккаунта, которую нужно обновить
        :param evm_pk: обновлённый приватный ключ (EVM)
        :param evm_address: обновлённый адрес (EVM)
        :param proxy: обновлённый прокси
        """
        has_changed = False

        if account_instance.evm_address != evm_address:
            account_instance.evm_address = evm_address
            has_changed = True

        if account_instance.proxy != proxy:
            account_instance.proxy = proxy
            has_changed = True

        if account_instance.email != email:
            account_instance.email = email
            has_changed = True

        if account_instance.twitter_token != twitter_token:
            account_instance.twitter_token = twitter_token
            has_changed = True

        if account_instance.discord_token != discord_token:
            account_instance.discord_token = discord_token
            has_changed = True

        if account_instance.user_agent != user_agent:
            account_instance.user_agent = user_agent
            has_changed = True

        if has_changed:
            ImportToDB.edited.append(account_instance)
            await session.merge(account_instance)
