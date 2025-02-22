import sys
import itertools

import asyncio

from data.config import logger
from utils.create_files import create_files
from db_api.database import initialize_db
from utils.adjust_policy import set_windows_event_loop_policy
from data.config import EVM_PKS, PROXIES, EMAIL_DATA, TWITTER_TOKENS, DISCORD_TOKENS, DISCORD_PROXYS, logger
from utils.import_info import get_info
from utils.user_menu import get_action, sahara_menu, discord_menu, galxe_menu, gobi_desert_menu, sahara_onchain_menu, jebroa_desert_menu
from db_api.start_import import ImportToDB
from settings.settings import ASYNC_TASK_IN_SAME_TIME
from tasks.main import get_start
from migrate import migrate
from utils.reset_count_progress import set_progress_to_zero
from utils.encrypt_params import check_encrypt_param
from utils.headers import compute_version, assemble_build


def main():
    global remaining_tasks

    while True:
        set_progress_to_zero()

        user_choice = get_action()

        semaphore = asyncio.Semaphore(ASYNC_TASK_IN_SAME_TIME)

        match user_choice:

            case "Import data to db":

                evm_pks = get_info(EVM_PKS)
                proxies = get_info(PROXIES)
                emails = get_info(EMAIL_DATA)
                twitter_tokens = get_info(TWITTER_TOKENS)
                discord_tokens = get_info(DISCORD_TOKENS)

                logger.info(f'\n\n\n'
                            f'Загружено в evm_pks.txt {len(evm_pks)} аккаунтов EVM \n'
                            f'Загружено в proxies.txt {len(proxies)} прокси \n'
                            f'Загружено в emails.txt {len(emails)} прокси \n'
                            f'Загружено в twitter_tokens.txt {len(twitter_tokens)} прокси \n'
                            f'Загружено в discord_tokens.txt {len(discord_tokens)} прокси \n'
                )

                cycled_proxies_list = itertools.cycle(proxies) if proxies else None

                formatted_data: list = [{
                        'evm_pk': evm_pk,
                        'proxy': next(cycled_proxies_list) if cycled_proxies_list else None,
                        'email': emails.pop(0) if emails else None,
                        'twitter_token': twitter_tokens.pop(0) if twitter_tokens else None,
                        'discord_token': discord_tokens.pop(0) if discord_tokens else None,
                    } for evm_pk in evm_pks
                ]

                asyncio.run(ImportToDB.add_info_to_db(accounts_data=formatted_data))

            case "SaharaAI":
                sahara_choice = sahara_menu()
                match sahara_choice:
                    case "Gobi Desert":
                        gobi_desert_choise = gobi_desert_menu()
                        match gobi_desert_choise:
                            case "Gobi Desert - Daily":
                                asyncio.run(get_start(semaphore, "Gobi Desert - Daily"))

                            case "Gobi Desert - Social Media":
                                asyncio.run(get_start(semaphore, "Gobi Desert - Social Media"))

                    case "Sahara on-chain":
                        sahara_onchain_choise = sahara_onchain_menu()
                        match sahara_onchain_choise:
                            case "SaharaAI - Daily Gobi Desert (on-chain)":
                                asyncio.run(get_start(semaphore, "SaharaAI - Daily Gobi Desert (on-chain)"))

                            case "SaharaAI Faucet":
                                asyncio.run(get_start(semaphore, "SaharaAI Faucet"))

                            case "SaharaAI Parse Native Balance":
                                asyncio.run(get_start(semaphore, "SaharaAI Parse Native Balance"))

                    case "Jebroa":
                        gobi_desert_choise = jebroa_desert_menu()
                        match gobi_desert_choise:
                            case "Account registration in Data Services Platform":
                                asyncio.run(get_start(semaphore, "Account registration in Data Services Platform"))

                    case "SaharaAI Parse ShardAmount":
                        asyncio.run(get_start(semaphore, "SaharaAI Parse ShardAmount"))

            case "Galxe":
                galxe_choice = galxe_menu()
                match galxe_choice:

                    case "Unlink bad Twitter token from Galxe":
                        asyncio.run(get_start(semaphore, "Unlink bad Twitter token from Galxe"))

            case "Discord":
                discord_choise = discord_menu()
                match discord_choise:
                    case "Accept invite to server":
                        native_build = compute_version()
                        logger.info(f'Успешно спрасил native_build приложения: {native_build}')
                        client_build = assemble_build()
                        logger.info(f'Успешно спрасил client_build приложения: {client_build}')
                        discord_tokens = get_info(DISCORD_TOKENS)
                        discord_proxys = get_info(DISCORD_PROXYS)

                        logger.info(f'\n\n\n'
                            f'Загружено в discord_tokens.txt {len(discord_tokens)} дискорд токенов \n'
                            f'Загружено в discord_proxys.txt {len(discord_proxys)} прокси \n'
                        )

                        formatted_discord_data: list = [{
                                'discord_token': discord_token,
                                'discord_proxy': discord_proxys.pop(0) if discord_proxys else None,
                                'native_build': native_build,
                                'client_build': client_build
                            } for discord_token in discord_tokens
                        ]
                    
                        if formatted_discord_data:
                            asyncio.run(get_start(semaphore, formatted_discord_data))
                        else:
                            logger.error(f'Вы не добавили дискорд прокси или дискорд токенов!!!')
                            sys.exit(1)
            
            case "Exit":
                sys.exit(1)


if __name__ == "__main__":
    #try:
        check_encrypt_param()
        asyncio.run(initialize_db())
        create_files()
        asyncio.run(migrate())
        set_windows_event_loop_policy()
        main()
    # except (SystemExit, KeyboardInterrupt):
    #     logger.info("Program closed")