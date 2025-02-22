import time
import uuid
import json
import random
import string
import asyncio
import traceback
from datetime import datetime, timezone, timedelta

from eth_account.messages import encode_defunct
from faker import Faker
from curl_cffi.requests.errors import RequestsError

from tasks.base import Base
from tasks.captcha.capmonster import Capmonster
from tasks.captcha.capsolver import Capsolver
from tasks.sahara import Sahara
from db_api.database import Accounts
from clients.eth.eth_client import EthClient
from clients.email.email_client import EmailClient
from utils.encrypt_params import get_private_key
from data.config import logger, tasks_lock
from settings.settings import NUMBER_OF_ATTEMPTS, SERVICE_TO_USE, SLEEP_FROM, SLEEP_TO, ADD_TWITTER
from clients.twitter.twitter_client import TwitterClient

    
class GalxeRequests(Base):

    def __init__(self, data: Accounts):
        super().__init__(data)

        self.eth_client = EthClient(
            private_key=get_private_key(data), proxy=self.data.proxy, user_agent=self.data.user_agent
        )

        self.auth_token = None
        if SERVICE_TO_USE == 'CAPMONSTER':
            self.capthca_service = Capmonster(self.data, self.async_session)
        elif SERVICE_TO_USE == 'CAPSOLVER':
            self.capthca_service = Capsolver(self.data, self.async_session)

    @Base.retry
    async def start_task(self, quest):
        try:
            self.quest = quest
            login_status = await self.start_login()

            if login_status:
                logger.info(f'[{self.data.id}] | {self.data.evm_address} | успешно авторизировался')
                registration_status = await self.check_if_address_register()

                if registration_status:
                    if not self.data.galxe_register:
                        self.data.galxe_register = True
                        async with tasks_lock:
                            await self.write_to_db()
                else:
                    status, msg = await self.start_of_registration()
                    if status:
                        self.data.galxe_register = True
                        async with tasks_lock:
                            await self.write_to_db()
                        msg = f'[{self.data.id}] | {self.data.evm_address} | успешно зарегистрировался на galxe. Account id: {msg}'
                        logger.success(msg)
                    else:
                        return False

            status, need_add_email, need_add_twitter, need_add_discord = await self.check_galxe_account_info()

            if status:
                msg = (f'[{self.data.id}] | {self.data.evm_address} | успешно получил информацию об аккаунте | '
                    f'need_add_email: {str(need_add_email).lower()} |'
                    f' need_add_twitter: {str(need_add_twitter).lower()} |'
                    f' need_add_discord: {str(need_add_discord).lower()}')
                logger.info(msg)

                if need_add_email:
                    if self.data.email:
                        status = await self.add_email_to_galxe()
                        if status:
                            logger.success(f'[{self.data.id}] | {self.data.evm_address} | успешно прикрепил почту к galxe')
                        else:
                            logger.error(f'[{self.data.id}] | {self.data.evm_address} | не смог прикрепить почту к galxe')
                            return False
                    else:
                        logger.error(f'[{self.data.id}] | {self.data.evm_address} | need add email data!')
                        return True

                # TODO: discord !!!

                if need_add_twitter and ADD_TWITTER and quest != "Unlink bad Twitter token from Galxe":
                    if self.data.twitter_token:
                        if self.data.twitter_account_status == 'OK':
                            status = await self.add_twitter_to_galxe()
                            if status:
                                logger.success(f'[{self.data.id}] | {self.data.evm_address} | успешно прикрепил твиттер к galxe')
                            else:
                                logger.error(f'[{self.data.id}] | {self.data.evm_address} | не смог прикрепить твиттер к galxe')
                                return False
                        else:
                            logger.error(f'[{self.data.id}] | {self.data.evm_address} | проверьте статус твиттер токена. Текущий статус: {self.data.twitter_account_status}')
                            return True
                    else:
                        logger.error(f'[{self.data.id}] | {self.data.evm_address} | need add twitter auth_token!')
                        return True

                if quest == "Gobi Desert - Daily":

                    status = await self.start_confirm_read_task(
                        tasks_list=['507361624877694976', '505649247018811392'], 
                        campaing_id='GCNLYtpFM5', 
                    )
                    if status:
                        status = await Sahara(self.data, self.async_session, self.eth_client).claim(['1002', '1001'])
                        if status:
                        
                            self.data.sahara_daily = datetime.now(timezone.utc)
                            async with tasks_lock:
                                await self.write_to_db()
                            return True
                        else:
                            return False
                        
                if quest == "Gobi Desert - Social Media":

                    if not self.data.twitter_token:
                        logger.error(f'{self.data.id} | {self.data.evm_address} | для выполнения этого задания у аккаунта должен быть twitter_token в базе данных')
                        return True
                    
                    if not self.data.gobi_desert_twitter_task:

                        if self.data.twitter_account_status != 'OK':
                            logger.error(f'[{self.data.id}] | {self.data.evm_address} | проверьте статус твиттер токена. Текущий статус: {self.data.twitter_account_status}')
                            return True
                        
                        logger.info(f'[{self.data.id}] | {self.data.evm_address} | Начинаю выполнять необходимые twitter таски...')
                        
                        status = await self.get_twitter_client()
                        if status:

                            status, follow_answer = await self.twitter_client.follow('1416402399384662021')
                            if status and follow_answer == 'SaharaLabsAI':

                                logger.success(f'[{self.data.id}] | {self.data.evm_address} | успешно подписался на @{follow_answer}')
                                await self.sleep()

                                for retweet in {'1884407902552883369', '1884775169480380652'}:
                                    status, answer = await self.twitter_client.retweet(retweet)

                                    if not status:
                                        logger.error(f'[{self.data.id}] | {self.data.evm_address} | {answer}')
                                        return False

                                    if 'You have already retweeted this Tweet' in answer:
                                        logger.warning(f'[{self.data.id}] | {self.data.evm_address} | {answer}')
                                    else:
                                        logger.success(f'[{self.data.id}] | {self.data.evm_address} | успешно сделал retweet - {retweet}')
                                    
                                    await self.sleep()
                                    
                                self.data.gobi_desert_twitter_task = True
                                async with tasks_lock:
                                    await self.write_to_db()
                                
                            else:
                                logger.error(f'[{self.data.id}] | {self.data.evm_address} | {follow_answer}')
                        else:
                            return True

                    status = await self.start_confirm_twitter_task(
                        tasks_list=['395230389519589376', '507370364607660032', '507364926881267712', '507370520795152384', '507365037103382528'], 
                        campaing_id='GCNDYtp2Rb', 
                    )
                    if status:
                        status = await Sahara(self.data, self.async_session, self.eth_client).claim(['1104', '1110', '1105', '1111', '1106'])
                        if status:
                            self.data.gobi_desert_social_media = True
                            async with tasks_lock:
                                await self.write_to_db()
                            return True
                        else:
                            return False
                    
                if quest == "Unlink bad Twitter token from Galxe":
                    if not need_add_twitter:
                        status = await self.remove_twitter_token_from_galxe()
                        if status:
                            self.data.twitter_token = ''
                            self.data.twitter_account_status = 'OK'
                            async with tasks_lock:
                                await self.write_to_db()
                            logger.success(f'[{self.data.id}] | {self.data.evm_address} | успешно отвязал твиттер токен от galxe!')
                            return True
                        logger.error(f'[{self.data.id}] | {self.data.evm_address} | не смог отвязать твиттер токен от galxe!')
                        return False
                    else:
                        self.data.twitter_token = ''
                        self.data.twitter_account_status = 'OK'
                        async with tasks_lock:
                            await self.write_to_db()
                        logger.warning(f'[{self.data.id}] | {self.data.evm_address} | у этого аккаунта нет привязанного твиттера к galxe!')
                        return True
                
        except RequestsError:
            logger.error(f'[{self.data.id}] | {self.data.evm_address} | Проблема с прокси! Проверьте прокси!')
            return False

        except Exception as error:
            logger.error(f'[{self.data.id}] | {self.data.evm_address} | неизвестная ошибка: {error}')
            print(traceback.print_exc())
            return False

    # SLEEP
    async def sleep(self):
        sleep_time = random.randint(SLEEP_FROM, SLEEP_TO)
        logger.debug(f'[{self.data.id}] | {self.data.evm_address} | сон между действиями {sleep_time} секунд')
        await asyncio.sleep(sleep_time)

    # PREPARE DATA
    @staticmethod
    def get_random_nonce(length=17):
        return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

    # PREPARE DATA
    @staticmethod
    def get_activity_time_login():
        issued_at = datetime.now(timezone.utc)
        expiration_time = issued_at + timedelta(days=7)
        issued_at_str = issued_at.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        expiration_time_str = expiration_time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        return issued_at_str, expiration_time_str

    # PREPARE DATA
    @staticmethod
    def get_random_request_id():
        return str(uuid.uuid4())

    # PREPARE DATA
    @staticmethod
    def get_random_username(min_lenght=6) -> str:
        return Faker().user_name().ljust(min_lenght, str(random.randint(1, 9)))

    # PREPARE DATA
    def get_main_headers(self):
        return {
            'accept': '*/*',
            'authority': 'graphigo.prd.galaxy.eco',
            'accept-language': 'en-US,en;q=0.9',
            'authorization': self.auth_token,
            'content-type': 'application/json',
            'origin': 'https://app.galxe.com',
            'request-id': self.get_random_request_id(),
            'sec-ch-ua': f'"Not_A Brand";v="8", "Chromium";v="{self.version}", "Google Chrome";v="{self.version}"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': f'"{self.platform}"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'cross-site',
            'user-agent': self.data.user_agent,
        }

    # LOGIN
    async def start_login(self):
        issued_at_str, expiration_time_str = self.get_activity_time_login()

        message = (
            'app.galxe.com wants you to sign in with your Ethereum account:\n'
            f'{self.data.evm_address}\n\n'
            'Sign in with Ethereum to the app.\n\n'
            'URI: https://app.galxe.com\n'
            'Version: 1\n'
            'Chain ID: 1\n'
            f'Nonce: {self.get_random_nonce()}\n'
            f'Issued At: {issued_at_str}\n'
            f'Expiration Time: {expiration_time_str}'
        )

        message_encoded = encode_defunct(text=message)
        signed_message = self.eth_client.account.sign_message(message_encoded)

        headers = {
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.9',
            'content-type': 'application/json',
            'origin': 'https://app.galxe.com',
            'platform': 'web',
            'request-id': self.get_random_request_id(),
            'sec-ch-ua': f'"Not_A(Brand";v="8", "Chromium";v="{self.version}", "Google Chrome";v="{self.version}"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': f'"{self.platform}"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'cross-site',
            'user-agent': self.data.user_agent,
        }

        json_data = {
            'operationName': 'SignIn',
            'variables': {
                'input': {
                    'address': self.data.evm_address,
                    'message': message,
                    'signature': signed_message.signature.hex(),
                    'addressType': 'EVM',
                    'publicKey': '1',
                },
            },
            'query': 'mutation SignIn($input: Auth) {\n  signin(input: $input)\n}',
        }
        
        response = await self.async_session.post(
            'https://graphigo.prd.galaxy.eco/query',
            headers=headers,
            json=json_data
        )

        if response.status_code == 200:
            answer = response.json()
            try:
                self.auth_token = answer['data']['signin']
                return True
            except (KeyError, TypeError):
                pass
        logger.warning(f'[{self.data.id}] | {self.data.evm_address} | не смог авторизироваться на galxe. Ответ сервера: {response.text}')
        return False

    # REGISTRATION
    async def check_if_address_register(self):

        headers = {
            'accept': '*/*',
            'authority': 'graphigo.prd.galaxy.eco',
            'accept-language': 'en-US,en;q=0.9',
            'content-type': 'application/json',
            'origin': 'https://app.galxe.com',
            'request-id': self.get_random_request_id(),
            'sec-ch-ua': f'"Not_A(Brand";v="8", "Chromium";v="{self.version}", "Google Chrome";v="{self.version}"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': f'"{self.platform}"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'cross-site',
            'user-agent': self.data.user_agent,
        }

        json_data = {
            'operationName': 'GalxeIDExist',
            'variables': {
                'schema': f'EVM:{self.data.evm_address}',
            },
            'query': 'query GalxeIDExist($schema: String!) {\n  galxeIdExist(schema: $schema)\n}',
        }

        response = await self.async_session.post(
            'https://graphigo.prd.galaxy.eco/query',
            headers=headers,
            json=json_data
        )

        if response.status_code == 200:
            answer = response.json()
            try:
                return answer["data"]["galxeIdExist"]
            except (KeyError, TypeError):
                pass
        msg = (f'{self.data.evm_address} | не удалось проверить зарегистрирован ли аккаунт. '
               f'Код ответа: {response.status_code}. Ответ: {response.text}')
        logger.warning(msg)
        return False

    # REGISTRATION
    async def check_if_username_exist(self, username):

        headers = self.get_main_headers()

        json_data = {
            'operationName': 'IsUsernameExisting',
            'variables': {
                'username': username,
            },
            'query': 'query IsUsernameExisting($username: String!) {\n  usernameExist(username: $username)\n}\n',
        }

        response = await self.async_session.post(
            'https://graphigo.prd.galaxy.eco/query',
            headers=headers,
            json=json_data
        )

        if response.status_code == 200:
            answer = response.json()
            try:
                return answer['data']['usernameExist']
            except KeyError:
                pass
        msg = f'[{self.data.id}] | {self.data.evm_address} | не удалось проверить свободен ли юзернейм. Ответ сервера: {response.text}'
        logger.warning(msg)
        return True

    # REGISTRATION
    async def start_of_registration(self):

        username = self.get_random_username()
        i = 0
        while i < NUMBER_OF_ATTEMPTS:
            username_exist = await self.check_if_username_exist(username)
            if not username_exist:
                break
            username = self.get_random_username()
            i += 1
            if i == 10:
                return False, 'не удалось проверить cвободен ли username'

        headers = self.get_main_headers()

        json_data = {
            'operationName': 'CreateNewAccount',
            'variables': {
                'input': {
                    'schema': f'EVM:{self.data.evm_address}',
                    'socialUsername': '',
                    'username': username,
                },
            },
            'query': 'mutation CreateNewAccount($input: CreateNewAccount!) {\n  createNewAccount(input: $input)\n}\n',
        }

        response = await self.async_session.post(
            'https://graphigo.prd.galaxy.eco/query',
            headers=headers,
            json=json_data
        )

        if response.status_code == 200:
            answer = response.json()
            try:
                if answer['data']['createNewAccount']:
                    return True, answer['data']['createNewAccount']
            except (KeyError, TypeError):
                pass
        logger.warning(f'[{self.data.id}] | {self.data.evm_address} | не удалось зарегистрироваться. Ответ сервера: {response.text}')
        return False, 'не удалось зарегистироваться'
    
    # ACC INFO
    async def check_galxe_account_info(self, check_user_id=False):

        headers = self.get_main_headers()

        query = (
            'query BasicUserInfo($address: String!) '
            '{\n  addressInfo(address: $address) {\n    id\n    username\n    avatar\n    address\n    '
            'evmAddressSecondary {\n      address\n      __typename\n    }\n    hasEmail\n    solanaAddress\n'
            '    aptosAddress\n    seiAddress\n    injectiveAddress\n    flowAddress\n    starknetAddress\n    '
            'bitcoinAddress\n    hasEvmAddress\n    hasSolanaAddress\n    hasAptosAddress\n    hasInjectiveAddress\n'
            '    hasFlowAddress\n    hasStarknetAddress\n    hasBitcoinAddress\n    hasTwitter\n    hasGithub\n    '
            'hasDiscord\n    hasTelegram\n    displayEmail\n    displayTwitter\n    displayGithub\n    displayDiscord\n'
            '    displayTelegram\n    displayNamePref\n    email\n    twitterUserID\n    twitterUserName\n    '
            'githubUserID\n    githubUserName\n    discordUserID\n    discordUserName\n    telegramUserID\n    '
            'telegramUserName\n    enableEmailSubs\n    subscriptions\n    isWhitelisted\n    isInvited\n    isAdmin\n'
            '    accessToken\n    __typename\n  }\n}\n'
        )

        json_data = {
            'operationName': 'BasicUserInfo',
            'variables': {
                'address': self.data.evm_address,
            },
            'query': query,
        }

        response = await self.async_session.post(
            'https://graphigo.prd.galaxy.eco/query',
            headers=headers,
            json=json_data
        )

        if response.status_code == 200:
            answer = response.json()
            if check_user_id:
                user_id = answer.get('data', False).get('addressInfo', False).get('id', False)
                if user_id:
                    return user_id
            else:
                need_add_email = False
                need_add_twitter = False
                need_add_discord = False
                try:
                    if not answer['data']['addressInfo']['hasEmail']:
                        need_add_email = True

                    if not answer['data']['addressInfo']['hasTwitter']:
                        need_add_twitter = True

                    if not answer['data']['addressInfo']['hasDiscord']:
                        need_add_discord = True

                    return True, need_add_email, need_add_twitter, need_add_discord
                except (KeyError, TypeError):
                    pass
        logger.warning(f'[{self.data.id}] | {self.data.evm_address} | не смог получить информацию об аккаунте. Ответ сервера: {response.text}')
        return False, False, False

    # ADD EMAIL
    async def request_to_add_email(self, solution):

        headers = self.get_main_headers()

        query = (
            'mutation SendVerifyCode($input: SendVerificationEmailInput!) '
            '{\n  sendVerificationCode(input: $input) {\n    code\n    message\n    __typename\n  }\n}'
        )

        json_data = {
            'operationName': 'SendVerifyCode',
            'variables': {
                'input': {
                    'address': f'EVM:{self.data.evm_address}',
                    'email': self.data.email.split(':')[0],
                    'captcha': {
                        'lotNumber': solution['lot_number'],
                        'captchaOutput': solution['captcha_output'],
                        'passToken': solution['pass_token'],
                        'genTime': solution['gen_time'],
                    },
                },
            },
            'query': query,
        }

        response = await self.async_session.post(
            'https://graphigo.prd.galaxy.eco/query',
            headers=headers,
            json=json_data
        )

        if response.status_code == 200:
            answer = response.json()
            try:
                if not answer['data']['sendVerificationCode']:
                    return True
            except (KeyError, TypeError):
                pass
        msg = f'[{self.data.id}] | {self.data.evm_address} | не удалось выслать запрос на прикрепление почты. Ответ сервера: {response.text}'
        logger.warning(msg)
        return False

    # ADD EMAIL
    async def send_email_verif_code(self, verif_code):

        headers = self.get_main_headers()

        query = ('mutation UpdateEmail($input: UpdateEmailInput!) '
                 '{\n  updateEmail(input: $input) {\n    code\n    message\n    __typename\n  }\n}\n')

        json_data = {
            'operationName': 'UpdateEmail',
            'variables': {
                'input': {
                    'address': f'EVM:{self.data.evm_address}',
                    'email': self.data.email.split(':')[0],
                    'verificationCode': verif_code,
                },
            },
            'query': query,
        }

        response = await self.async_session.post(
            'https://graphigo.prd.galaxy.eco/query',
            headers=headers,
            json=json_data
        )

        if response.status_code == 200:
            answer = response.json()
            if 'errors' in answer:
                return False
            elif not answer['data']['updateEmail']:
                return True
        return False
    
    # ADD EMAIL
    async def add_email_to_galxe(self):
        solution = await self.capthca_service.wait_for_geetest_gcaptcha()
        if solution:
            status = await self.request_to_add_email(solution)
            if status:
                logger.info(f'[{self.data.id}] | {self.data.evm_address} | успешно отправил запрос на прикрепление почты.')
                await asyncio.sleep(10)
                verif_code = await EmailClient(
                    f'{self.data.id} | {self.data.evm_address} ',
                    self.data.email.split(':')[0], 
                    self.data.email.split(':')[1]
                ).get_code()
                if verif_code:
                    logger.info(f'[{self.data.id}] | {self.data.evm_address} | email verify code успешно получен.')
                    status = await self.send_email_verif_code(verif_code)
                    if status:
                        logger.info(f'[{self.data.id}] | {self.data.evm_address} | email успешно прикреплен')
                        return True
                    else:
                        logger.warning(f'[{self.data.id}] | {self.data.evm_address} | не смог прикрепить email')
                        return False
                else:
                    logger.warning(f'[{self.data.id}] | {self.data.evm_address} | не смог получить код верификации почты')
                    return False

        return False
    
    # PREPARE TASK
    async def prepare_galxe_task(self, solution, cred_id, campaign_id):

        headers = self.get_main_headers()

        query = (
            'mutation AddTypedCredentialItems($input: MutateTypedCredItemInput!) '
            '{\n  typedCredentialItems(input: $input) {\n    id\n    __typename\n  }\n}'
        )

        json_data = {
            'operationName': 'AddTypedCredentialItems',
            'variables': {
                'input': {
                    'credId': cred_id,
                    'campaignId': campaign_id,
                    'operation': 'APPEND',
                    'items': [
                        f'EVM:{self.data.evm_address}',
                    ],
                    'captcha': {
                        'lotNumber': solution['lot_number'],
                        'captchaOutput': solution['captcha_output'],
                        'passToken': solution['pass_token'],
                        'genTime': solution['gen_time'],
                    },
                },
            },
            'query': query,
        }

        response = await self.async_session.post(
            'https://graphigo.prd.galaxy.eco/query',
            headers=headers,
            json=json_data
        )

        if response.status_code == 200:
            answer = response.json()
            if 'failed to verify recaptcha token' in str(answer):
                logger.warning(f'{self.data.address} | проблема c подтверждением капчи! Проверьте W')
                return False
            try:
                return True, answer.get('data', {}).get('typedCredentialItems', {}).get('id', False)
            except AttributeError:
                logger.warning(f'{self.data.address} | ошибка, ответ сервера: {answer}')
                return False
        return False, 'notId'

    # CONFIRM TASK
    async def confirm_galxe_task(self, cred_id, campaign_id='', solution={}, twitter=False):

        headers = self.get_main_headers()

        query = (
            'mutation SyncCredentialValue($input: SyncCredentialValueInput!) {\n  syncCredentialValue(input: $input) '
            '{\n    value {\n      address\n      spaceUsers {\n        follow\n        points\n        '
            'participations\n        __typename\n      }\n      campaignReferral {\n        count\n        '
            '__typename\n      }\n      gitcoinPassport {\n        score\n        lastScoreTimestamp\n        '
            '__typename\n      }\n      walletBalance {\n        balance\n        __typename\n      }\n      '
            'multiDimension {\n        value\n        __typename\n      }\n      allow\n      survey {\n        '
            'answers\n        __typename\n      }\n      quiz {\n        allow\n        correct\n        __typename\n'
            '      }\n      __typename\n    }\n    message\n    __typename\n  }\n}'
        )

        json_data = {
            'operationName': 'SyncCredentialValue',
            'variables': {
                'input': {
                    'syncOptions': {
                        'credId': cred_id,
                        'address': self.data.evm_address,
                    },
                },
            },
            'query': query,
        }

        if twitter:
            json_data['variables']['input']['syncOptions']['twitter'] = {
                'campaignID': campaign_id,
                'captcha': {
                    'lotNumber': solution['lot_number'],
                    'captchaOutput': solution['captcha_output'],
                    'passToken': solution['pass_token'],
                    'genTime': solution['gen_time'],
                },
            }

        response = await self.async_session.post(
            'https://graphigo.prd.galaxy.eco/query',
            headers=headers,
            json=json_data
        )

        try:
            if response.status_code == 200:
                answer = response.json()
                return answer.get('data', {}).get('syncCredentialValue', {}).get('value', {}).get('allow', False)
            return False
        except AttributeError:
            
            return False

    # PREPARE AND CONFIRM READ TASK
    async def prepare_and_confrim_galxe_batch_tasks(self, task_list, campaign_id, twitter=False):
        for task in task_list:
            logger.info(f'[{self.data.id}] | {self.data.evm_address} | пытаюсь подтвердить task {task}')
            capthca = await self.capthca_service.wait_for_geetest_gcaptcha()
            if capthca:
                status = await self.prepare_galxe_task(solution=capthca, cred_id=task, campaign_id=campaign_id)
                if status:
                    if twitter:
                        capthca = await self.capthca_service.wait_for_geetest_gcaptcha()
                        if capthca:
                            status = await self.confirm_galxe_task(cred_id=task, campaign_id=campaign_id, solution=capthca, twitter=True)
                    else:
                        status = await self.confirm_galxe_task(cred_id=task)

                    if not status:
                        return False
                else:
                    return False
                
            logger.success(f'[{self.data.id}] | {self.data.evm_address} | успешно подтвердил task {task}')
        return True
    
    # PREPARE AND CONFIRM READ TASK
    async def start_confirm_read_task(self, tasks_list, campaing_id):
        return await self.prepare_and_confrim_galxe_batch_tasks(
            task_list=tasks_list,
            campaign_id=campaing_id
        )
    
    # CREATE TW client
    async def get_twitter_client(self):
        self.twitter_client = TwitterClient(
            data=self.data, 
            session=self.async_session,
            version=self.version,
            platform=self.platform
        )
        status, msg = await self.twitter_client.login()
        if not status and msg != 'OK':
            logger.error(f'[{self.data.id}] | {self.data.evm_address} | {msg}')
            self.data.twitter_account_status = self.twitter_client.account_status
            async with tasks_lock:
                await self.write_to_db()
            return False
        return True

    # ADD TWITTER TO GALXE
    async def galxe_twitter_check_account(self, tweet_url):

        headers = self.get_main_headers()

        query = (
            'mutation checkTwitterAccount($input: VerifyTwitterAccountInput!) '
            '{\n  checkTwitterAccount(input: $input) {\n    address\n    twitterUserID\n    twitterUserName\n'
            '    __typename\n  }\n}'
        )

        json_data = {
            'operationName': 'checkTwitterAccount',
            'variables': {
                'input': {
                    'address': f'EVM:{self.data.evm_address}',
                    'tweetURL': tweet_url,
                },
            },
            'query': query,
        }

        response = await self.async_session.post(
            'https://graphigo.prd.galaxy.eco/query',
            headers=headers,
            json=json_data
        )

        if response.status_code == 200:
            answer = response.json()
            if not answer:
                answer = {}
            if (
                    answer.get('data', {}).get('checkTwitterAccount', {}).get('twitterUserID', {}) ==
                    self.twitter_client.username
            ):
                return True
        msg = (f'{self.data.address} | не удалось выслать запрос на проверку твиттер аккаунта.'
               f' Ответ сервера: {response.text}')
        logger.warning(msg)
        return False
    
    # ADD TWITTER TO GALXE
    async def galxe_twitter_verify_account(self, tweet_url):

        headers = self.get_main_headers()

        query = (
            'mutation VerifyTwitterAccount($input: VerifyTwitterAccountInput!) '
            '{\n  verifyTwitterAccount(input: $input) {\n    address\n    twitterUserID\n    twitterUserName\n'
            '    __typename\n  }\n}'
        )

        json_data = {
            'operationName': 'VerifyTwitterAccount',
            'variables': {
                'input': {
                    'address': f'EVM:{self.data.evm_address}',
                    'tweetURL': tweet_url,
                },
            },
            'query': query,
        }

        response = await self.async_session.post(
            'https://graphigo.prd.galaxy.eco/query',
            headers=headers,
            json=json_data
        )

        if response.status_code == 200:
            answer = response.json()
            if not answer:
                answer = {}
            if (
                    answer.get('data', {}).get('verifyTwitterAccount', {}).get('twitterUserName', {}) ==
                    self.twitter_client.username
            ):
                return True
        logger.warning(f'{self.data.address} | не удалось прикрепить твиттер аккаунт. Ответ сервера: {response.text}')
        return False

    # ADD TWITTER TO GALXE
    async def add_twitter_to_galxe(self):
        user_id = await self.check_galxe_account_info(check_user_id=True)
        
        if user_id:
            
            status = await self.get_twitter_client()
            if status:
                tweet_text = f'Verifying my Twitter account for my #GalxeID gid:{user_id} @Galxe\n\n'
                status, tweet_id = await self.twitter_client.post_tweet(tweet_text)
                
                if status:

                    if self.twitter_client.username:
                        tweet_url = f'https://x.com/{self.twitter_client.username}/status/{tweet_id}'
                        status = await self.galxe_twitter_check_account(tweet_url)
                        if status:
                            status = await self.galxe_twitter_verify_account(tweet_url)
                            if status:
                                return True
                    else:
                        logger.error(f'[{self.data.id}] | {self.data.evm_address} | не смог вытащить username.')

                else:
                    logger.error(f'[{self.data.id}] | {self.data.evm_address} | {tweet_id}')

        return False
    
    # TWITTER TASK CONFIRM        
    async def start_confirm_twitter_task(self, tasks_list, campaing_id):
        return await self.prepare_and_confrim_galxe_batch_tasks(
            task_list=tasks_list,
            campaign_id=campaing_id,
            twitter=True
        )

    # REMOVE TWITTER TOKEN FROM GALXE
    async def remove_twitter_token_from_galxe(self): 
        
        headers = self.get_main_headers()

        query = (
            'mutation DeleteSocialAccount($input: DeleteSocialAccountInput!) {\n  deleteSocialAccount(input: $input)'
            ' {\n    code\n    message\n    __typename\n  }\n}'
        )

        json_data = {
            'operationName': 'DeleteSocialAccount',
            'variables': {
                'input': {
                    'address': f'EVM:{self.data.evm_address}',
                    'type': 'TWITTER',
                },
            },
            'query': query,
        }

        response = await self.async_session.post(
            'https://graphigo.prd.galaxy.eco/query', 
            headers=headers, 
            json=json_data
        )

        if response.status_code == 200:
            answer = response.json()

            if not answer.get('data', {}).get('deleteSocialAccount', True):
                return True
        logger.warning(f'{self.data.address} | не удалось отвязать твиттер от galxe')
        return False
