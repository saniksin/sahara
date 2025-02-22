import uuid
import base64
import secrets
from functools import wraps

from data.session import BaseAsyncSession
from db_api.database import Accounts


class TwitterClient:

    def __init__(self, data: Accounts, session: BaseAsyncSession, version: str, platform: str):
        self.data = data
        self.auth_token = data.twitter_token
        self.version = version
        self.platfrom = platform

        self.async_session = session
        self.ct0 = ''
        self.username = ''
        self.account_status = ''

    async def login(self):
        cookies = {
            'auth_token': self.auth_token
        }

        data = {
            'debug': 'true',
            'log': '[{"_category_":"client_event","format_version":2,"triggered_on":1736641509177,"event_info":"String","event_namespace":{"page":"app","action":"error","client":"m5"},"client_event_sequence_start_timestamp":1736640638874,"client_event_sequence_number":130,"client_app_id":"3033300"},{"_category_":"client_event","format_version":2,"triggered_on":1736641510151,"event_info":"String","event_namespace":{"page":"app","action":"error","client":"m5"},"client_event_sequence_start_timestamp":1736640638874,"client_event_sequence_number":131,"client_app_id":"3033300"}]',
        }
        
        response = await self.async_session.post('https://x.com/i/api/1.1/jot/client_event.json', headers=self.base_headers(), cookies=cookies, data=data)

        if response.status_code == 200:
            self.ct0 = self.async_session.cookies['ct0']
            self.account_status = 'OK'
            return True, 'OK'
        
        if "Could not authenticate you" in response.text:
            self.account_status = "BAD TOKEN"
            return False, 'Не смог послать первый запрос. Плохой твиттер токен! Ответ сервера: Could not authenticate you'

        self.account_status = 'UKNOWN'
        return False, f'Не смог послать первый запрос. Проверьте твиттер токен! Ответ сервера: {response.text}'

    # @staticmethod
    # def open_session(func):
    #     @wraps(func)
    #     async def wrapper(self, *args, **kwargs):
    #         #try:
    #             status, msg = await self.login()
    #             if status and msg == "OK":
    #                 return await func(self, *args, **kwargs)
    #             elif not status and msg == "BAD TOKEN":
    #                 return False, msg
    #             else:
    #                 return False, msg
    #         # except Exception as e:
    #         #     return False, 'BAD'
    #     return wrapper

    @staticmethod
    def generate_client_transaction_id():
        """
        Генерирует случайный x-client-transaction-id в формате Base64.
        """
        random_bytes = secrets.token_bytes(70)  
        transaction_id = base64.b64encode(random_bytes).decode('ascii').rstrip('=')  
        return transaction_id
    
    @staticmethod
    def generate_client_uuid():
        """
        Генерирует случайный x-client-uuid.
        """
        return str(uuid.uuid4())  

    def base_headers(self):
        return {
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.9',
            'authorization': 'Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA',
            'priority': 'u=1, i',
            'sec-ch-ua': f'"Google Chrome";v="{self.version}", "Chromium";v="{self.version}", "Not_A Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': f'"{self.platfrom}"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': self.data.user_agent,
            'x-client-transaction-id': self.generate_client_transaction_id(),
            'x-client-uuid': self.generate_client_uuid(),
            'x-twitter-active-user': 'yes',
            'x-twitter-auth-type': 'OAuth2Session',
            'x-twitter-client-language': 'en',
        }

    async def post_tweet(self, tweet_text):

        headers = self.base_headers()
        headers['cache-control'] = 'no-cache'
        headers['content-type'] = 'application/json'
        headers['origin'] = 'https://x.com'
        headers['pragma'] = 'no-cache'
        headers['referer'] = 'https://x.com/home'
        headers['sec-ch-ua'] = f'"Not A(Brand";v="8", "Chromium";v="{self.version}", "Google Chrome";v="{self.version}"'
        headers['x-csrf-token'] = self.ct0

        json_data = {
            'variables': {
                'tweet_text': tweet_text,
                'dark_request': False,
                'media': {
                    'media_entities': [],
                    'possibly_sensitive': False,
                },
                'semantic_annotation_ids': [],
                'disallowed_reply_options': None,
            },
            'features': {
                'premium_content_api_read_enabled': False,
                'communities_web_enable_tweet_community_results_fetch': True,
                'c9s_tweet_anatomy_moderator_badge_enabled': True,
                'responsive_web_grok_analyze_button_fetch_trends_enabled': False,
                'responsive_web_grok_analyze_post_followups_enabled': True,
                'responsive_web_jetfuel_frame': False,
                'responsive_web_grok_share_attachment_enabled': True,
                'responsive_web_edit_tweet_api_enabled': True,
                'graphql_is_translatable_rweb_tweet_is_translatable_enabled': True,
                'view_counts_everywhere_api_enabled': True,
                'longform_notetweets_consumption_enabled': True,
                'responsive_web_twitter_article_tweet_consumption_enabled': True,
                'tweet_awards_web_tipping_enabled': False,
                'responsive_web_grok_analysis_button_from_backend': True,
                'creator_subscriptions_quote_tweet_preview_enabled': False,
                'longform_notetweets_rich_text_read_enabled': True,
                'longform_notetweets_inline_media_enabled': True,
                'profile_label_improvements_pcf_label_in_post_enabled': True,
                'rweb_tipjar_consumption_enabled': True,
                'responsive_web_graphql_exclude_directive_enabled': True,
                'verified_phone_label_enabled': False,
                'articles_preview_enabled': True,
                'rweb_video_timestamps_enabled': True,
                'responsive_web_graphql_skip_user_profile_image_extensions_enabled': False,
                'freedom_of_speech_not_reach_fetch_enabled': True,
                'standardized_nudges_misinfo': True,
                'tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled': True,
                'responsive_web_grok_image_annotation_enabled': True,
                'responsive_web_graphql_timeline_navigation_enabled': True,
                'responsive_web_enhance_cards_enabled': False,
            },
            'queryId': 'UYy4T67XpYXgWKOafKXB_A',
        }

        response = await self.async_session.post(
            'https://x.com/i/api/graphql/UYy4T67XpYXgWKOafKXB_A/CreateTweet',
            headers=headers,
            json=json_data,
        )

        if response.status_code == 200:
            tweet_id = response.json().get('data', {}).get('create_tweet', {}).get('tweet_results', {}).get('result', {}).get('rest_id', '')
            if tweet_id:
                if not self.username:
                    self.username = response.json().get("data", {}).get("create_tweet", {}).get("tweet_results", {}).get("result", {}).get("core", {}).get("user_results", {}).get("result", {}).get("legacy", {}).get("screen_name", "")
                return True, tweet_id
            
        return False, f'Не смог создать tweet | status code: {response.status_code} | ответ сервера: {response.text}'

    async def follow(self, user_id):

        headers = {
            'sec-ch-ua-platform': f'"{self.platfrom}"',
            'x-csrf-token': self.ct0,
            'authorization': 'Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA',
            'Referer': 'https://x.com/',
            'X-Client-UUID': self.generate_client_uuid(),
            'Accept-Language': 'en-US,en;q=0.9',
            'sec-ch-ua': f'"Not A(Brand";v="8", "Chromium";v="{self.version}", "Google Chrome";v="{self.version}"',
            'x-twitter-client-language': 'en',
            'sec-ch-ua-mobile': '?0',
            'x-twitter-active-user': 'yes',
            'x-client-transaction-id': self.generate_client_transaction_id(),
            'x-twitter-auth-type': 'OAuth2Session',
            'User-Agent': self.data.user_agent,
            'content-type': 'application/x-www-form-urlencoded',
        }

        data = {
            'include_profile_interstitial_type': '1',
            'include_blocking': '1',
            'include_blocked_by': '1',
            'include_followed_by': '1',
            'include_want_retweets': '1',
            'include_mute_edge': '1',
            'include_can_dm': '1',
            'include_can_media_tag': '1',
            'include_ext_is_blue_verified': '1',
            'include_ext_verified_type': '1',
            'include_ext_profile_image_shape': '1',
            'skip_status': '1',
            'user_id': user_id,
        }

        response = await self.async_session.post(
            'https://x.com/i/api/1.1/friendships/create.json',
            headers=headers, 
            data=data
        )

        if response.status_code == 200:
            return True, response.json().get('screen_name', '')
        
        return False, f'Не смог подписаться на {user_id} | status code: {response.status_code} | ответ сервера: {response.text}'

    async def retweet(self, tweet_id):

        headers = self.base_headers()
        headers['cache-control'] = 'no-cache'
        headers['content-type'] = 'application/json'
        headers['origin'] = 'https://x.com'
        headers['pragma'] = 'no-cache'
        headers['referer'] = 'https://x.com/home'
        headers['sec-ch-ua'] = f'"Not A(Brand";v="8", "Chromium";v="{self.version}", "Google Chrome";v="{self.version}"'
        headers['x-csrf-token'] = self.ct0

        json_data = {
            'variables': {
                'tweet_id': tweet_id,
                'dark_request': False,
            },
            'queryId': 'ojPdsZsimiJrUGLR1sjUtA',
        }

        response = await self.async_session.post(
            'https://x.com/i/api/graphql/ojPdsZsimiJrUGLR1sjUtA/CreateRetweet',
            headers=headers,
            json=json_data,
        )

        if response.status_code == 200:
            retweet_id = response.json().get("data", {}).get("create_retweet", {}).get("retweet_results", {}).get("result", {}).get("rest_id", "")
            if retweet_id:
                return True, retweet_id
            if 'You have already retweeted this Tweet' in response.text:
                return True, f'Не смог создать retweet | status code: {response.status_code}. Ответ сервера: {response.json().get("errors", [{}])[0].get("message", "")}'
        
        return False, f'Не смог создать retweet | status code: {response.status_code} | ответ сервера: {response.text}'
