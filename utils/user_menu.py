import inquirer
from termcolor import colored
from inquirer.themes import load_theme_from_dict as loadth


# MAIN MENU
def get_action() -> str:
    """Пользователь выбирает действие через меню"""

    theme = {
        'Question': {
            'brackets_color': 'bright_yellow'
        },
        'List': {
            'selection_color': 'bright_blue'
        },
    }

    question = [
        inquirer.List(
            "action",
            message=colored('Выберите ваше действие', 'light_yellow'),
            choices=[
                'Import data to db',
                'SaharaAI',
                'Galxe',
                'Discord',
                'Exit'
            ]
        )
    ]

    return inquirer.prompt(question, theme=loadth(theme))['action']


# SAHARA AI
def sahara_menu() -> str:
    """Меню для Sahara"""
    theme = {
        'Question': {
            'brackets_color': 'bright_yellow'
        },
        'List': {
            'selection_color': 'bright_blue'
        },
    }

    question = [
        inquirer.List(
            "swap_action",
            message=colored('Выберите действие для SaharaAI', 'light_yellow'),
            choices=[
                "Gobi Desert",
                "Sahara on-chain",
                "Jebroa",
                "SaharaAI Parse ShardAmount",
                "SaharaAI Parse Airdrop",
                "Exit"
            ]
        )
    ]

    return inquirer.prompt(question, theme=loadth(theme))['swap_action']


def gobi_desert_menu() -> str:
    """Меню для Gobi Desert Menu"""
    theme = {
        'Question': {
            'brackets_color': 'bright_yellow'
        },
        'List': {
            'selection_color': 'bright_blue'
        },
    }

    question = [
        inquirer.List(
            "swap_action",
            message=colored('Выберите действие для Gobi Desert', 'light_yellow'),
            choices=[
                "Gobi Desert - Daily",
                "Gobi Desert - Social Media",
                "Exit"
            ]
        )
    ]

    return inquirer.prompt(question, theme=loadth(theme))['swap_action']


def jebroa_desert_menu() -> str:
    """Меню для Gobi Desert Menu"""
    theme = {
        'Question': {
            'brackets_color': 'bright_yellow'
        },
        'List': {
            'selection_color': 'bright_blue'
        },
    }

    question = [
        inquirer.List(
            "swap_action",
            message=colored('Выберите действие для Gobi Desert', 'light_yellow'),
            choices=[
                "Account registration in Data Services Platform",
                "Exit"
            ]
        )
    ]

    return inquirer.prompt(question, theme=loadth(theme))['swap_action']


def sahara_onchain_menu() -> str:
    """Меню для Sahara onchain menu"""
    theme = {
        'Question': {
            'brackets_color': 'bright_yellow'
        },
        'List': {
            'selection_color': 'bright_blue'
        },
    }

    question = [
        inquirer.List(
            "swap_action",
            message=colored('Выберите действие для Sahara on-chain', 'light_yellow'),
            choices=[
                "SaharaAI - Daily Gobi Desert (on-chain)",
                "SaharaAI Faucet",
                "SaharaAI Parse Native Balance",
                "Exit"
            ]
        )
    ]

    return inquirer.prompt(question, theme=loadth(theme))['swap_action']
                

# DISCORD MENU
def discord_menu() -> str:
    """Меню для Discord"""
    theme = {
        'Question': {
            'brackets_color': 'bright_yellow'
        },
        'List': {
            'selection_color': 'bright_blue'
        },
    }

    question = [
        inquirer.List(
            "swap_action",
            message=colored('Выберите действие для Discord', 'light_yellow'),
            choices=[
                "Accept invite to server",
                "Exit"
            ]
        )
    ]

    return inquirer.prompt(question, theme=loadth(theme))['swap_action']


# GALXE MENU
def galxe_menu() -> str:
    """Меню для GALXE"""
    theme = {
        'Question': {
            'brackets_color': 'bright_yellow'
        },
        'List': {
            'selection_color': 'bright_blue'
        },
    }

    question = [
        inquirer.List(
            "swap_action",
            message=colored('Выберите действие для Galxe', 'light_yellow'),
            choices=[
                "Unlink bad Twitter token from Galxe",
                "Exit"
            ]
        )
    ]

    return inquirer.prompt(question, theme=loadth(theme))['swap_action']

