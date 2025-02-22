import asyncio

from data.session import BaseAsyncSession


async def create_24captch_task(async_session: BaseAsyncSession, api_key, site_key, page_url, proxy, proxy_type, rq_data='', enterprise=False):
    url = "https://24captcha.online/in.php"
    payload = {
        "key": api_key,
        "sitekey": site_key,
        "pageurl": page_url,
        "json": 1,
        "method": "hcaptcha",
        "proxy": proxy,
        "proxytype": proxy_type,
    }
    
    if rq_data:
        payload['rq_data'] = rq_data
    if enterprise:
        payload['enterprise'] = enterprise

    response = await async_session.post(url, json=payload)
    if response.status_code == 200:
        data = response.json()
        if data.get("status") == 1:
            return True, data.get("request")
        else:
            return False, data.get('error_text')
    else:
        return False, f"Failed to create task: HTTP {response.status_code}"


async def get_24captcha_task_result(async_session: BaseAsyncSession, api_key, task_id):
    url = "https://24captcha.online/res.php"
    payload = {
        "key": api_key,
        "action": "get",
        "id": task_id,
        "json": 1
    }
    
    while True:
        response = await async_session.post(url, json=payload)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == 1:
                return True, data.get("request")
            elif data.get("request") == "CAPCHA_NOT_READY":
                await asyncio.sleep(10) 
            else:
                return False, data.get('request')
        else:
            return False, f"Failed to get task result: HTTP {response.status_code}"