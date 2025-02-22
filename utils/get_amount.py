import random


def get_amount(amount: list[float, float], number=9):

    return round(random.uniform(amount[0], amount[1]), number)