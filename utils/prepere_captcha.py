from settings.settings import HCAPTCHA_SERVICE_TO_USE, API_KEY_24_CAPTCHA, API_KEY_BESTCAPTCHA
from data.config import logger
from tasks.captcha.capthca24 import create_24captch_task, get_24captcha_task_result
from tasks.captcha.bestcapthca import create_bestcaptcha_task, get_bestcaptcha_task_result
from data.session import BaseAsyncSession


async def get_hcaptcha_solution(proxy, session: BaseAsyncSession, site_key, page_url, rq_data=False, enterprise=False):
        PROXY = proxy.replace('http://', '')
        PROXY_TYPE = 'HTTP'

        # create task
        if HCAPTCHA_SERVICE_TO_USE == "CAPTCHA24":
            status, task_id = await create_24captch_task(
                async_session=session, 
                api_key=API_KEY_24_CAPTCHA,
                site_key=site_key,
                page_url=page_url,
                proxy=PROXY, 
                proxy_type=PROXY_TYPE,
                rq_data=rq_data,
                enterprise=enterprise
            )
       
        elif HCAPTCHA_SERVICE_TO_USE == "BESTCAPTCHA":
            status, task_id = await create_bestcaptcha_task(
                async_session=session, 
                access_token=API_KEY_BESTCAPTCHA, 
                site_key=site_key, 
                page_url=page_url, 
                proxy=PROXY,
            )

        if not status:
            return False, task_id
        
        # recieve solution
        if HCAPTCHA_SERVICE_TO_USE == "CAPTCHA24":
            status, g_recaptcha_response = await get_24captcha_task_result(
                async_session=session,
                api_key=API_KEY_24_CAPTCHA,
                task_id=task_id
            )

        elif HCAPTCHA_SERVICE_TO_USE == "BESTCAPTCHA":
            status, g_recaptcha_response = await get_bestcaptcha_task_result(
                async_session=session,
                access_token=API_KEY_BESTCAPTCHA,
                task_id=task_id
            )

        return status, g_recaptcha_response

