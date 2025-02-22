def get_info(path):
    with open(path, 'r', encoding='utf-8-sig') as file:
        info: list[str] = [row.strip() for row in file]
    return info
