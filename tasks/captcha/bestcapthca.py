import asyncio

from data.session import BaseAsyncSession


async def create_bestcaptcha_task(async_session: BaseAsyncSession, access_token, site_key, page_url, proxy=None, proxy_type="HTTP", payload=None, domain=None):
    url = "https://bcsapi.xyz/api/captcha/hcaptcha"
    request_payload = {
        "access_token": access_token,
        "page_url": page_url,
        "site_key": site_key,
        "user_agent": async_session.user_agent
    }

    # Добавляем необязательные параметры, если они указаны
    if proxy:
        request_payload["proxy"] = proxy
        request_payload["proxy_type"] = proxy_type
    if payload:
        request_payload["payload"] = payload
    if domain:
        request_payload["domain"] = domain

    # Отправляем запрос на создание задачи
    response = await async_session.post(url, json=request_payload)
    if response.status_code == 200:
        data = response.json()
        if data.get("status") == "submitted":
            return True, data.get("id")
        else:
            return False, f"Error: {data.get('error', 'Unknown error')}"
    else:
        return False, f"Failed to create task: HTTP {response.status_code}"


async def get_bestcaptcha_task_result(async_session: BaseAsyncSession, access_token, task_id):
    url = f"https://bcsapi.xyz/api/captcha/{task_id}?access_token={access_token}"

    while True:
        # Отправляем запрос на получение результата
        response = await async_session.get(url)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "completed":
                return True, data.get("solution")
            elif data.get("status") == "pending":
                await asyncio.sleep(5)  # Ожидаем перед следующим запросом
            else:
                return False, f"Error: {data.get('error', 'Unknown error')}"
        else:
            return False, f"Failed to get task result: HTTP {response.status_code}"
