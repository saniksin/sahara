import uuid
import json
import random
import asyncio

import aiohttp
from data.session import BaseAsyncSession
from functools import wraps
from settings.settings import (
    NUMBER_OF_ATTEMPTS, 
    DISCORD_SITE_KEY,  
    DISCORD_INVITE, 
)
from data.config import logger
from utils.headers import create_x_context_properties, create_x_super_properties
from utils.prepere_captcha import get_hcaptcha_solution


class DiscordInvite:
    
    def __init__(self, account_data, quest):

        self.proxy = account_data['discord_proxy']
        self.client_build = account_data['client_build']
        self.native_build = account_data['native_build']
        if 'http' not in self.proxy:
            self.proxy = f'http://{self.proxy}'

        self.discord_token = account_data['discord_token']
        self.async_session: BaseAsyncSession = BaseAsyncSession(
            proxy=self.proxy,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            timeout=5   
        )

        self.acc_index = quest
        self.invite_code = DISCORD_INVITE
        self.session_id = self.generate_session_id()
        
        self.ws = None
        self.client_session = None
        self.gateway_url = "wss://gateway.discord.gg/?v=9&encoding=json"
        self.heartbeat_interval = None
        self.sequence = None

    @staticmethod
    def generate_session_id():
        return uuid.uuid4().hex

    @staticmethod
    def open_session(func):
        @wraps(func)
        async def wrapper(self, *args, **kwargs):

            self.async_session.headers.update({
                "authorization": self.discord_token,
                "x-super-properties": create_x_super_properties(
                    native_build_number=self.native_build,
                    client_build_number=self.client_build
                )
            })

            headers = {
                'authority': 'discord.com',
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'accept-language': 'en-US,en;q=0.9',
                'sec-ch-ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-fetch-dest': 'document',
                'sec-fetch-mode': 'navigate',
                'sec-fetch-site': 'none',
                'sec-fetch-user': '?1',
                'upgrade-insecure-requests': '1',
                'user-agent': self.async_session.user_agent,
            }

            self.async_session.cookies.update({
                'cf_clearance': 'ci1vlr9efAE_Pe5XxOxenwFuK6OPvbpdtNwt8O_.D6g-1736817731-1.2.1.1-uTb1SslQlUYOJjEgrPeDRngfA7GYWcpjo88JnxTf2gt89_cJfy.tTvjLKXOvYli_xW_NobI9BU8kX8JROYblcAxyOd.dJSf4PlDrteLBjD2AoRSLwjZinstFA2YPw0c8z3l4Qmnj3MvFXrX9KGjgHaGHp63jlsL9k9ebProP93GMulNGv6yWk_WGij_TZp.wEo3buRH6uzcdIQEhebsFghX0ALPz4GDj0B9eMflSKDWQ_e3aKdxKeKt.5NcFFTm0hV35xunq__EaT9nL1MGUVKnmzTsf80MicBTzrvvVSuU',
                'locale': 'en-US',
            })

            await self.async_session.get("https://discord.com/login", headers=headers)

            return await func(self, *args, **kwargs)
        
        return wrapper
    
    async def connect(self):
        """
        Подключаемся к Discord Gateway через веб-сокет (с прокси, если указано).
        """

        connector_args = {"proxy": self.proxy} if self.proxy else {}

        # Открываем aiohttp-сессию вручную
        self.client_session = aiohttp.ClientSession(**connector_args)

        # Подключаемся к Gateway
        self.ws = await self.client_session.ws_connect(
            self.gateway_url,
            headers={"Authorization": self.discord_token}
        )

        # Ждём HELLO
        hello_payload = await self.ws.receive_json()
        self.heartbeat_interval = hello_payload["d"]["heartbeat_interval"]

        # Запускаем heartbeat loop
        asyncio.create_task(self.heartbeat_loop())

        # Отправляем IDENTIFY
        asyncio.create_task(self.identify())

        # Слушаем Gateway
        asyncio.create_task(self.listen_gateway())

    async def close(self):
        """
        Закрытие WebSocket и HTTP-сессии.
        """
        # Закрываем веб-сокет
        if self.ws:
            await self.ws.close()

        # Закрываем aiohttp.ClientSession
        if self.client_session:
            await self.client_session.close()



    async def identify(self):
        """
        Отправляет IDENTIFY пакет.
        """
        identify_payload = {
            "op": 2,
            "d": {
                "token": self.discord_token,
                "capabilities": 30717,
                "properties": {
                    "os": "Windows",
                    "browser": "Chrome",
                    "device": "",
                    "system_locale": "en-US",
                    "has_client_mods": False,
                    "browser_user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                    "browser_version": "131.0.0.0",
                    "os_version": "10",
                    "referrer": "",
                    "referring_domain": "",
                    "referrer_current": "",
                    "referring_domain_current": "",
                    "release_channel": "stable",
                    "client_build_number": 359425,
                    "client_event_source": None
                },
                "presence": {
                    "status": "uknown",
                    "since": 0,
                    "activities": [],
                    "afk": False,
                },
                "compress": False,
                "client_state": {
                    "guild_versions": {},
                },
            },
        }
        try:
            await self.ws.send_json(identify_payload)
        except Exception as e:
            pass
            #print(f"Ошибка при отправке IDENTIFY: {e}")

    async def send_join(self):
        """
        Отправляет IDENTIFY пакет.
        """
        identify_payload = {
            "op":37,
            "d":{
                "subscriptions":{
                    "1020496431959785503":{
                        "typing": True,
                        "activities": True,
                        "threads": True
                    }
                }
            }
        }
        try:
            await self.ws.send_json(identify_payload)
        except Exception as e:
            pass
            #print(f"Ошибка при отправке IDENTIFY: {e}")

    async def listen_gateway(self):
        """
        Слушаем входящие события от Gateway.
        """
        async for message in self.ws:
            data = json.loads(message.data)
            op = data["op"]
            t = data.get("t")
            s = data.get("s")
            if s is not None:
                self.sequence = s

            if op == 0 and t == "READY":
                #print(data)
                self.session_id = data["d"]["session_id"]
                user = data["d"]["user"]
                logger.info(f'[{self.acc_index}] | {self.discord_token} | Авторизовались как {user['username']}#{user['discriminator']} | session_id = {self.session_id}')

    async def heartbeat_loop(self):
        """
        Периодически отправляет HEARTBEAT (op=1).
        """
        while True:
            await asyncio.sleep(self.heartbeat_interval / 1000.0)
            payload = {
                "op": 1,
                "d": self.sequence,
            }
            try:
                await self.ws.send_json(payload)
            except Exception as e:
                #print(f"Ошибка при отправке HEARTBEAT: {e}")
                break

    async def get_guild_id(self) -> tuple[bool, str, str]:
        try:
            response = await self.async_session.get(f"https://discord.com/api/v9/invites/{self.invite_code}")

            if "You need to verify your account" in response.text:
                logger.error(f"[{self.acc_index}] | Account needs verification (Email code etc).")
                return "verification_failed", "", False

            location_guild_id = response.json()['guild_id']
            location_channel_id = response.json()['channel']['id']

            return True, location_guild_id, location_channel_id

        except Exception as err:
            logger.error(f"[{self.acc_index}] | {self.discord_token} | Failed to get guild ids: {err}")
            return False, "", "", 

    @open_session
    async def accept_invite(self, my_try=100):
        while True:

            headers = {
                'accept': '*/*',
                'accept-encoding': 'gzip, deflate, br',
                'accept-language': 'en-US,en;q=0.9',
                'content-type': 'application/json',
                'origin': 'https://discord.com',
                'priority': 'u=1, i',
                'referer': 'https://discord.com/channels/@me',
                'sec-ch-ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'user-agent': self.async_session.user_agent,
                'x-context-properties': self.x_content_properties,
                'x-debug-options': 'bugReporterEnabled',
                'x-discord-locale': 'en-US',
                'x-discord-timezone': 'Europe/Paris',
                'x-super-properties': create_x_super_properties(
                    native_build_number=self.native_build,
                    client_build_number=self.client_build
                ),
                "host": "discord.com",
            }

            json_data = {
                'session_id': self.session_id
            }

            response = await self.async_session.post(
                f"https://discord.com/api/v9/invites/{self.invite_code}",
                json=json_data,
                headers=headers
            )

            if 'The user is banned from this guild' in response.text:
                return False, f'[{self.acc_index}] | {self.discord_token} | Banned on the server!'

            if "You need to update your app to join this server." in response.text or "captcha_rqdata" in response.text:
                #return False, f'[{self.acc_index}] | {self.discord_token} | capthca.. I will try again!'
                    
                captcha_rqdata = response.json()["captcha_rqdata"]
                captcha_rqtoken = response.json()["captcha_rqtoken"]

                logger.info(f"[{self.acc_index}] | {self.discord_token} | Creating hCAPTCHA task...")

                status, g_recaptcha_response = await get_hcaptcha_solution(
                    proxy=self.proxy,
                    session=self.async_session,
                    site_key=DISCORD_SITE_KEY,
                    page_url="https://discord.com/",
                    rq_data=captcha_rqdata,
                    enterprise=True
                )

                if not status:
                    return False, f'[{self.acc_index}] | {self.discord_token} | {g_recaptcha_response}'
                logger.info(f"[{self.acc_index}] {self.discord_token} | Received captcha solution... Trying to join the server")

                headers = {
                    'accept': '*/*',
                    'accept-language': 'en-US,en;q=0.9',
                    'accept-encoding': 'gzip, deflate, br',
                    'content-type': 'application/json',
                    'origin': 'https://discord.com',
                    'referer': f'https://discord.com/invite/{self.invite_code}',
                    'sec-ch-ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
                    'sec-ch-ua-mobile': '?0',
                    'sec-ch-ua-platform': '"Windows"',
                    'sec-fetch-dest': 'empty',
                    'sec-fetch-mode': 'cors',
                    'sec-fetch-site': 'same-origin',
                    'user-agent': self.async_session.user_agent,
                    'x-captcha-key': g_recaptcha_response,
                    'x-captcha-rqtoken': captcha_rqtoken,
                    'x-context-properties': self.x_content_properties,
                    'x-debug-options': 'bugReporterEnabled',
                    'x-discord-locale': 'en-US',
                    'x-discord-timezone': 'Europe/Paris',
                    'x-super-properties': create_x_super_properties(
                        native_build_number=self.native_build,
                        client_build_number=self.client_build
                    ),
                    "host": "discord.com",
                }

                json_data = {
                    'session_id': self.session_id,
                    # "captcha_key": g_recaptcha_response,
                    # "captcha_rqtoken": captcha_rqtoken
                }
                
                response = await self.async_session.post(
                    f"https://discord.com/api/v9/invites/{self.invite_code}",
                    json=json_data,
                    headers=headers
                )

                # print(self.acc_index, response.status_code)
                # print(self.acc_index, response.text)
                if 'The user is banned from this guild' in response.text:
                    return False, f'[{self.acc_index}] | {self.discord_token} | Banned on the server!'

                if response.status_code == 200 and response.json().get('type') == 0:
                    return True, f'[{self.acc_index}] | {self.discord_token} | Joined the server!'

                elif "Unknown Message" in response.text:
                    return False, f'[{self.acc_index}] | {self.discord_token} | Unknown Message: {response.text}'
                
                return False, f'[{self.acc_index}] | {self.discord_token} | Wrong invite response: {response.text}'
                
            elif response.status_code == 200 and response.json().get("type") == 0:
                return True, f'[{self.acc_index}] | {self.discord_token} | Already joined the server!'

            elif "Unauthorized" in response.text:
                return False, f'[{self.acc_index}] | {self.discord_token} | Incorrect discord token or your account is blocked.'

            elif "You need to verify your account in order to" in response.text:
                return False, f'[{self.acc_index}] | {self.discord_token} | Account needs verification (Email code etc).'
            
            
            return False, f'[{self.acc_index}] | {self.discord_token} | Unknown error: {response.text}'


    async def agree_with_server_rules(self, location_guild_id, location_channel_id):
        response = await self.async_session.get(
            f"https://discord.com/api/v9/guilds/{location_guild_id}/member-verification?with_guild=false&invite_code={self.invite_code}"
        )
        if "Unknown Guild" in response.text:
            return True, f"[{self.acc_index}] | {self.discord_token} | This guild does not require agreement with the rules."

        headers = {
            'authority': 'discord.com',
            'accept': '*/*',
            'content-type': 'application/json',
            'origin': 'https://discord.com',
            'referer': f'https://discord.com/channels/{location_guild_id}/{location_channel_id}',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'x-debug-options': 'bugReporterEnabled',
            'x-discord-locale': 'en-US',
        }

        json_data = {
            'version': response.json()['version'],
            'form_fields': [
                {
                    'field_type': response.json()['form_fields'][0]['field_type'],
                    'label': response.json()['form_fields'][0]['label'],
                    'description': response.json()['form_fields'][0]['description'],
                    'automations': response.json()['form_fields'][0]['automations'],
                    'required': True,
                    'values': response.json()['form_fields'][0]['values'],
                    'response': True,
                },
            ],
        }

        response = await self.async_session.put(
            f"https://discord.com/api/v9/guilds/{location_guild_id}/requests/@me",
            json=json_data
        )

        if 'You need to verify your account' in response.text:
            return False, f"[{self.acc_index}] | {self.discord_token} | Account needs verification (Email code etc)."
        
        elif 'This user is already a member' in response.text:
            return True, f"[{self.acc_index}] | {self.discord_token} | This user is already a member!"
        
        if "application_status" in response.text:
            if response.json()['application_status'] == "APPROVED":
                return True, f"[{self.acc_index}] | {self.discord_token} | Agreed to the server rules."
            else:
                logger.error(f"{self.account_index} | Failed to agree to the server rules: {response.text}")
                return False, f"[{self.acc_index}] | {self.discord_token} | Failed to agree to the server rules: {response.text}"

        else:
            return False, f"[{self.acc_index}] | {self.discord_token} | Failed to agree to the server rules: {response.json()['rejection_reason']}"


    async def click_to_emoji(self, location_guild_id, location_channel_id):

        headers = {
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.9',
            'origin': 'https://discord.com',
            'priority': 'u=1, i',
            'referer': f'https://discord.com/channels/{location_guild_id}/{location_channel_id}',
            'sec-ch-ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'x-debug-options': 'bugReporterEnabled',
            'x-discord-locale': 'en-US',
            'x-discord-timezone': 'Europe/Paris',
            'x-super-properties': create_x_super_properties(
                native_build_number=self.native_build,
                client_build_number=self.client_build
            ),
        }

        params = {
            'location': 'Message Inline Button',
            'type': '0',
        }

        response = await self.async_session.put(
            f'https://discord.com/api/v9/channels/{location_channel_id}/messages/1320859543931977808/reactions/%E2%9C%85/%40me',
            params=params,
            headers=headers,
        )

        if response.status_code == 204:
            return True, f'[{self.acc_index}] | {self.discord_token} | Успешно нажал на emoji'

        return False, f'[{self.acc_index}] | {self.discord_token} | Не смог нажать на emoji. Ответ сервера: {response.text} | Status_code: {response.status_code}'
                

    @open_session
    async def start_accept_discord_invite(self):
        for num in range(1, NUMBER_OF_ATTEMPTS + 1):
            try:
                logger.info(f'[{self.acc_index}] | {self.discord_token} | попытка {num}/{NUMBER_OF_ATTEMPTS}')
                
                await self.connect()
                await asyncio.sleep(random.randint(120, 150))

                status, location_guild_id, location_channel_id = await self.get_guild_id()

                if not status:
                    logger.error(f'[{self.acc_index}] | {self.discord_token} | не смог получить location_guild_id и location_channel_id')
                    await self.close()
                    continue

                self.x_content_properties = create_x_context_properties(location_guild_id, location_channel_id)

                status, answer = await self.accept_invite()

                if "Banned" in answer or "Incorrect discord token or your account is blocked" in answer:
                    logger.error(answer)
                    await self.close()
                    return False

                if not status:
                    logger.error(answer)
                    await self.close()
                    continue
                
                logger.success(answer)
                
                status, answer = await self.agree_with_server_rules(location_guild_id, location_channel_id)
                if not status:
                    logger.error(answer)
                    await self.close()
                    continue

                logger.success(answer)

                if self.invite_code == 'eclipse-fnd':


                    status, answer = await self.click_to_emoji(location_guild_id, location_channel_id)
                    if not status:
                        logger.error(answer)
                        await self.close()
                        continue

                    logger.success(answer)

                return True   
            except Exception as e:
                logger.error(f"[{self.acc_index}] | {self.discord_token} | Attempt {num}/{NUMBER_OF_ATTEMPTS} failed due to: {e}")
                if num == NUMBER_OF_ATTEMPTS:
                    return False
                await self.close()
                await asyncio.sleep(1)  

        return False
