import time
import random
import uuid
import asyncio
import secrets

from eth_account.messages import encode_defunct
from eth_keys import keys

from db_api.database import Accounts
from data.session import BaseAsyncSession
from data.config import logger, tasks_lock
from settings.settings import SAHARA_REF_CODE, USE_REF_LINK, SAHARA_FAUCET_SITE_KEY, MIN_BALANCE, PERCENT_NATIVE_TO_TX, SLEEP_FROM, SLEEP_TO
from clients.eth.eth_client import EthClient
from utils.encrypt_params import get_private_key
from tasks.base import Base
from utils.prepere_captcha import get_hcaptcha_solution
from datetime import datetime, timezone
from data.models import TokenAmount, Networks
from tasks.captcha.capsolver_turnstile import CapsolverTurnstile
                      

class Sahara(Base):

    def __init__(self, data: Accounts, async_session: BaseAsyncSession | None = None, eth_client: EthClient | None = None, network=Networks.Ethereum):
        super().__init__(data=data, async_session=async_session)

        self.version = self.data.user_agent.split('Chrome/')[1].split('.')[0]
        self.platform = self.data.user_agent.split(' ')[1][1:].replace(';', '')
        if self.platform == "Macintosh":
            self.platform = "MacOS"
        elif self.platform == "X11":
            self.platform = "Linux"

        if eth_client:
            self.eth_client = eth_client
        else:
            self.eth_client = EthClient(
                private_key=get_private_key(data), network=network, proxy=self.data.proxy, user_agent=self.data.user_agent
            )


    def get_main_headers(self):
        return {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'en-US,en;q=0.9',
            'authorization': 'Bearer null',
            'content-type': 'application/json',
            'origin': 'https://legends.saharalabs.ai',
            'priority': 'u=1, i',
            'referer': 'https://legends.saharalabs.ai/',
            'sec-ch-ua': f'"Not_A(Brand";v="8", "Chromium";v="{self.version}", "Google Chrome";v="{self.version}"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': f'"{self.platform}"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': self.data.user_agent,
        }   
    
    async def get_code_challange(self):
        
        json_data = {
            'address': self.data.evm_address.lower(),
            'timestamp': str(int(time.time() * 1000)),
        }

        response = await self.async_session.post(
            'https://legends.saharalabs.ai/api/v1/user/challenge', 
            headers=self.get_main_headers(), 
            json=json_data
        )

        if response.status_code == 200:
            return True, response.json().get('challenge')
        logger.error(f'[{self.data.id}] | {self.data.evm_address} не смог получить code_challange от SaharaAI')
        return False, ''

    @staticmethod
    def get_random_request_id():
        return str(uuid.uuid4())


    async def get_auth_token(self, code_challange):
        message = (
            'Sign in to Sahara!\n'
            f'Challenge:{code_challange}'
        )

        message_encoded = encode_defunct(text=message)
        signed_message = self.eth_client.account.sign_message(message_encoded)
        
        json_data = {
            'address': self.data.evm_address.lower(),
            'sig': signed_message.signature.hex(),
            'walletUUID': self.get_random_request_id(),
            'walletName': 'MetaMask',
            'timestamp': str(int(time.time() * 1000)),
        }

        if USE_REF_LINK:
            json_data['referralCode'] = SAHARA_REF_CODE

        response = await self.async_session.post(
            'https://legends.saharalabs.ai/api/v1/login/wallet', 
            headers=self.get_main_headers(), 
            json=json_data
        )

        if response.status_code == 200:
            return True, response.json().get('accessToken')
        logger.error(f'[{self.data.id}] | {self.data.evm_address} не смог получить accessToken от SaharaAI')
        return False, ''

    async def claim_daily_tasks(self, auth_token, task_list):

        headers = self.get_main_headers()
        headers['authorization'] = f'Bearer {auth_token}'

        for task in task_list:

            logger.info(f'[{self.data.id}] | {self.data.evm_address} пробую подтвердить {task} на SaharaAI')

            json_data = {
                'taskID': task,
                'timestamp': str(int(time.time() * 1000)),
            }

            response = await self.async_session.post(
                'https://legends.saharalabs.ai/api/v1/task/flush', 
                headers=headers, 
                json=json_data
            )

            # СЛИП для прогрузки!!!
            await asyncio.sleep(10)

            json_data = {
                'taskID': task,
                'timestamp': str(int(time.time() * 1000)),
            }

            response = await self.async_session.post(
                'https://legends.saharalabs.ai/api/v1/task/claim', 
                headers=headers, 
                json=json_data
            )

            if response.status_code == 200:
                if '[{"type":"asset","assetID":"1"' or '[{"type":"asset","assetID":"2","amount":"5"}]' in response.text:
                    continue
                
                return False, f'[{self.data.id}] | {self.data.evm_address} не смог склеймить задание {task}. Ответ сервера: {response.text}'
            
            elif f"reward of task: {task} has been claimed" in response.text:
                continue

            else:
                return False, f'[{self.data.id}] | {self.data.evm_address} не смог склеймить задание {task}. Ответ сервера: {response.text}'
        
        return True, f'[{self.data.id}] | {self.data.evm_address} успешно склеймил Sahara-daily задания.'


    async def claim(self, task_list):

        status, code_challange = await self.get_code_challange()
        if status:
            status, auth_token = await self.get_auth_token(code_challange)
            if status:
                status, msg = await self.claim_daily_tasks(auth_token, task_list)
                if 'не смог' in msg:
                    logger.error(msg)
                    return False
                else:
                    logger.success(msg)
                    return True
                
        return False
    
    async def faucet_token_request(self, cf_turnstile_response):
        headers = {
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.9',
            'content-type': 'application/json',
            'cf-turnstile-response': cf_turnstile_response,
            'origin': 'https://faucet.saharalabs.ai',
            'priority': 'u=1, i',
            'referer': 'https://faucet.saharalabs.ai/',
            'sec-ch-ua': f'"Not_A(Brand";v="8", "Chromium";v="{self.version}", "Google Chrome";v="{self.version}"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': f'"{self.platform}"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'cross-site',
            'user-agent': self.data.user_agent,
        }

        json_data = {
            'address': self.data.evm_address,
        }

        response = await self.async_session.post(
            'https://faucet-api.saharaa.info/api/claim2', 
            headers=headers, 
            json=json_data,
            timeout=120000
        )  
        if response.status_code == 200:

            return True, f'[{self.data.id}] | {self.data.evm_address} | успешно сделал запрос на получение тестовых токенов. Ответ сервера: {response.json().get('msg', '')}'

        if "You have exceeded the rate limit. Please wait" in response.text:
            return True, f'[{self.data.id}] | {self.data.evm_address} | Не смог заклеймить кран, код ответа: {response.status_code} | сообщение: {response.json().get('msg', "Не смог вытащить ошибку")}'
        
        return False, f'[{self.data.id}] | {self.data.evm_address} | Не смог заклеймить кран, код ответа: {response.status_code} | msg: {response.text}'
    

    @Base.retry
    async def claim_faucet(self):
        # status, hcaptcha_response = await get_hcaptcha_solution(
        #     proxy=self.data.proxy,
        #     session=self.async_session,
        #     site_key=SAHARA_FAUCET_SITE_KEY,
        #     page_url='https://faucet.saharalabs.ai/',
        #     rq_data=False,
        #     enterprise=False
        # )

        captcha_solution = await CapsolverTurnstile(self.data, self.async_session).wait_for_turnstile_captcha()

        if captcha_solution:
            status, msg = await self.faucet_token_request(captcha_solution)
            if status:
                self.data.sahara_faucet = datetime.now(timezone.utc)
                async with tasks_lock:
                    await self.write_to_db()
                if "Не смог заклеймить" in msg:
                    logger.warning(msg)
                else:
                    logger.success(msg)
                return True
            else:
                logger.error(msg)
                return False
        else:
            logger.error(f'[{self.data.id}] | [{self.data.evm_address}] | не смог получить решение капчи...')
            return False

    async def get_shard_amount(self, auth_token):
        headers = self.get_main_headers()
        headers['authorization'] = f'Bearer {auth_token}'

        response = await self.async_session.post(
            'https://legends.saharalabs.ai/api/v1/user/info', 
            headers=headers
        )
        if response.status_code == 200:
            return True, response.json().get('shardAmount', 0)
        logger.error(f'[{self.data.id}] | {self.data.evm_address} | Не смог cпарсить кол-во shard amount, код ответа: {response.status_code} | сообщение: {response.text}')
        return False, 0

    @Base.retry
    async def parse_shard_amount(self):
        status, code_challange = await self.get_code_challange()
        if status:
            status, auth_token = await self.get_auth_token(code_challange)
            if status:
                status, shard_amount = await self.get_shard_amount(auth_token)
                if status:
                    self.data.sahara_shard_amount = shard_amount
                    async with tasks_lock:
                        await self.write_to_db()
                    logger.success(f'[{self.data.id}] | {self.data.evm_address} | успешно спарсил кол-во shard amount. Текущее кол-во: {shard_amount}')
                    return True
        
        return False
    
    async def _update_balance(self):
        sahara_balance = TokenAmount(await self.eth_client.w3.eth.get_balance(self.data.evm_address), wei=True)
        self.data.sahara_balance = float(sahara_balance.Ether)
        self.data.finished_parse_sahara_balance = True
        async with tasks_lock:
            await self.write_to_db()
        logger.success(f'[{self.data.id}] | {self.data.evm_address} | успешно спарсил баланс. Текущий баланс: {sahara_balance.Ether} {Networks.SaharaAI.coin_symbol}')
        return True

    @Base.retry
    async def parse_native_balance(self):
        return await self._update_balance()

    @Base.retry
    async def claim_gobi_desert_onchain_daily(self):
        sahara_balance = TokenAmount(await self.eth_client.w3.eth.get_balance(self.data.evm_address), wei=True)
        if float(sahara_balance.Ether) < MIN_BALANCE:
            logger.error(
                f'[{self.data.id}] | {self.data.evm_address} | текущего баланса не достаточно для совершения каких-либо действий. '
                f'Текущий балансе: {sahara_balance.Ether} {Networks.SaharaAI.coin_symbol} | Минимальный баланса {MIN_BALANCE} {Networks.SaharaAI.coin_symbol}'
            )
            return True
        
        percent_sahara_to_make_tx = secrets.randbelow(
            PERCENT_NATIVE_TO_TX[1] - PERCENT_NATIVE_TO_TX[0] + 1
        ) + PERCENT_NATIVE_TO_TX[0]
        get_tx_sahara_amount = TokenAmount(int((sahara_balance.Wei / 100) * percent_sahara_to_make_tx), wei=True)

        if float(get_tx_sahara_amount.Ether) + MIN_BALANCE > sahara_balance.Ether:
            logger.error(
                f'[{self.data.id}] | {self.data.evm_address} | текущего баланса не достаточно для совершения транзакции. '
                f'Текущий балансе: {sahara_balance.Ether} {Networks.SaharaAI.coin_symbol} | Необходимо для действия: {float(get_tx_sahara_amount.Ether) + MIN_BALANCE} {Networks.SaharaAI.coin_symbol}'
            )
            return True

        status, tx_hash = await self.eth_client.send_native(data=self.data, amount=get_tx_sahara_amount, address=self.data.evm_address)
        if status:
            logger.success(f"[{self.data.id}] | {self.data.evm_address} | Транзакция успешно выполнена! Хэш: {Networks.SaharaAI.explorer}{tx_hash}")
            sleep_time = random.randint(SLEEP_FROM, SLEEP_TO)
            logger.info(f"[{self.data.id}] | {self.data.evm_address} | сон {sleep_time} секунд перед действием клейма...")
            await asyncio.sleep(sleep_time)
            status = await self.claim(task_list=['1004'])
            sahara_balance = TokenAmount(await self.eth_client.w3.eth.get_balance(self.data.evm_address), wei=True)
            if status:
                self.data.sahara_onchain_daily = datetime.now(timezone.utc)
                self.data.sahara_balance = float(sahara_balance.Ether)
                async with tasks_lock:
                    await self.write_to_db()
                return True
            
        return False
    
    def get_saharalabs_main_headers(self):
        return {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'en-US,en;q=0.9',
            'content-type': 'application/json',
            'origin': 'https://app.saharalabs.ai',
            'priority': 'u=1, i',
            'referer': 'https://app.saharalabs.ai/',
            'sec-ch-ua': f'"Not_A(Brand";v="8", "Chromium";v="{self.version}", "Google Chrome";v="{self.version}"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': f'"{self.platform}"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': self.data.user_agent,
        }
    
    async def get_saharalabs_login_msg(self):

        json_data = {
            'address': self.data.evm_address,
            'chainId': '0x04c7e1',
        }

        response = await self.async_session.post(
            'https://app.saharalabs.ai/v1/auth/generate-message', 
            headers=self.get_saharalabs_main_headers(), 
            json=json_data
        )

        if response.status_code == 200:
            answer = response.json()
            if answer.get('success'):
                return True, answer

        logger.error(f'[{self.data.id}] | {self.data.evm_address} | Не смог получить get_saharalabs_login_msg, код ответа: {response.status_code} | msg: {response.text}')
        return False, ''

    async def login_saharalabs(self, message):
        
        message_encoded = encode_defunct(text=message)
        signed_message = self.eth_client.account.sign_message(message_encoded)

        private_key = get_private_key(self.data)
        if private_key.startswith('0x'):
            private_key = private_key[2:]
        
        public_key = keys.PrivateKey(bytes.fromhex(private_key)).public_key
        json_data = {
            'message': message,
            'pubkey': str(public_key),
            'role': 7,
            'signature': signed_message.signature.hex(),
            'walletType': 'io.metamask',
        }

        response = await self.async_session.post('https://app.saharalabs.ai/v1/auth/login', headers=self.get_saharalabs_main_headers(), json=json_data)
        if response.status_code == 200:
            answer = response.json()
            if answer.get('success'):
                self.saharalabs_token = answer.get('data', {}).get('token', '')
                if self.saharalabs_token:
                    return True
        logger.error(f'[{self.data.id}] | {self.data.evm_address} | Не смог сделать login_saharalabs, код ответа: {response.status_code} | msg: {response.text}')
        return False

    @Base.retry
    async def start_account_registration_in_dsp(self):
        status, msg = await self.get_saharalabs_login_msg()
        if not status:
            return False
        
        message = msg.get('data', {}).get('message', '')
        if not msg:
            logger.error(f'[{self.data.id}] | {self.data.evm_address} | Не смог получить msg start_account_registration_in_dsp, возможно изменился формат. Текущий msg: {msg}')
            return False

        status = await self.login_saharalabs(message)
        if not status:
            return False
        
        status = await self.claim(task_list=['2001'])
        if status:
            self.data.account_registration_in_DSP = True
            async with tasks_lock:
                await self.write_to_db()
            logger.success(f'[{self.data.id}] | {self.data.evm_address} | успешно сделал start_account_registration_in_dsp')
            return True
        
        return False