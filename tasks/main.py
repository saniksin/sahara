import asyncio
import traceback
import random

from data.config import logger, tasks_lock, completed_tasks, remaining_tasks, DISCORD_PROXYS, DISCORD_TOKENS, DISCORD_TOKEN_FAILS, DISCORD_TOKEN_SUCCESS
from db_api.models import Accounts
from db_api.database import get_accounts
from settings.settings import SLEEP_BEETWEEN_ACTIONS, ACCOUNT_SHUFFLE
from tqdm import tqdm
from tasks import GalxeRequests
from tasks.discord_inviter import DiscordInvite
from tasks.sahara import Sahara
from data.models import Networks


async def get_start(semaphore, quest: str):
    #try:
        if isinstance(quest, str):
            accounts: list[Accounts] = await get_accounts(quest)

            # ДЛЯ ОПРЕДЛЕННОГО АККА
            # all_accounts: list[Accounts] = await get_accounts(quest)
            # accounts = []
            # for address in all_accounts:
            #     if address.evm_address == "":
            #         accounts.append(address)
            #         break

        else:
            accounts: list[dict] = quest
            
        
        if len(accounts) != 0:
            if ACCOUNT_SHUFFLE:
                random.shuffle(accounts)
            logger.info(f'Всего задач: {len(accounts)}')
            tasks = []
            if isinstance(quest, str):
                for account_data in accounts:
                    task = asyncio.create_task(start_limited_task(semaphore, accounts, account_data, quest=quest))
                    tasks.append(task)
            else:
                account_number = 1
                for account_data in accounts:
                    task = asyncio.create_task(start_limited_task(semaphore, accounts, account_data, quest=account_number))
                    tasks.append(task)
                    account_number += 1

            await asyncio.wait(tasks)
        else:
            msg = (f'Не удалось начать действие, причина: нет подходящих аккаунтов для выбранного действия.')
            logger.warning(msg)
    # except Exception as e:
    #     pass

async def start_limited_task(semaphore, accounts, account_data, quest):
    #try:
        async with semaphore:
            status = await start_task(account_data, quest)
            async with tasks_lock:
                completed_tasks[0] += 1
                remaining_tasks[0] = len(accounts) - completed_tasks[0]

            logger.warning(f'Всего задач: {len(accounts)}. Осталось задач: {remaining_tasks[0]}')

            if isinstance(quest, str):
                if remaining_tasks[0] > 0 and status:
                    # Генерация случайного времени ожидания
                    sleep_time = random.randint(SLEEP_BEETWEEN_ACTIONS[0], SLEEP_BEETWEEN_ACTIONS[1])

                    logger.info(f"Ожидание {sleep_time} между действиями...")
                    
                    await asyncio.sleep(sleep_time)
            else:
                async with tasks_lock:
                    if status:
                        with open(DISCORD_TOKEN_SUCCESS, 'a') as file:
                            file.write(f"{account_data['discord_token']}\n")
                    else:
                        with open(DISCORD_TOKEN_FAILS, 'a') as file:
                            file.write(f"{account_data['discord_token']}\n")
                    
                    # Читаем все токены из файла
                    with open(DISCORD_TOKENS, 'r') as file:
                        discord_tokens: list[str] = [row.strip() for row in file]

                    # Удаляем токен, если он есть
                    discord_tokens = [token for token in discord_tokens if token != account_data['discord_token']]

                    # Перезаписываем файл без указанного токена
                    with open(DISCORD_TOKENS, 'w') as file:
                        file.write('\n'.join(discord_tokens) + '\n')

                    # Читаем все прокси из файла
                    with open(DISCORD_PROXYS, 'r') as file:
                        discord_proxys: list[str] = [row.strip() for row in file]

                    # Удаляем прокси, если он есть
                    discord_proxys = [proxy for proxy in discord_proxys if proxy != account_data['discord_proxy']]

                    # Перезаписываем файл без указанного прокси
                    with open(DISCORD_PROXYS, 'w') as file:
                        file.write('\n'.join(discord_proxys) + '\n')


async def start_task(account_data, quest):

    if isinstance(quest, str):
            
        if quest in {"SaharaAI Faucet"}:
            async with Sahara(data=account_data) as sahara:
                return await sahara.claim_faucet()
        
        elif quest in {"SaharaAI Parse ShardAmount"}:
            async with Sahara(data=account_data) as sahara:
                return await sahara.parse_shard_amount()
            
        elif quest in {"SaharaAI Parse Native Balance"}:
            async with Sahara(data=account_data, network=Networks.SaharaAI) as sahara:
                return await sahara.parse_native_balance()

        elif quest in {"SaharaAI - Daily Gobi Desert (on-chain)"}:
            async with Sahara(data=account_data, network=Networks.SaharaAI) as sahara:
                return await sahara.claim_gobi_desert_onchain_daily()

        elif quest in {"Gobi Desert - Daily", "Gobi Desert - Social Media", "Unlink bad Twitter token from Galxe"}:
            async with GalxeRequests(data=account_data) as galxe:
                return await galxe.start_task(quest)
        
        elif quest in {"Account registration in Data Services Platform"}:
            async with Sahara(data=account_data, network=Networks.SaharaAI) as sahara:
                return await sahara.start_account_registration_in_dsp()
            
        elif quest in {"SaharaAI Parse Airdrop"}:
            async with Sahara(data=account_data, network=Networks.SaharaAI) as sahara:
                return await sahara.parse_airdrop()

    else:
        discord = DiscordInvite(account_data, quest)
        return await discord.start_accept_discord_invite()
