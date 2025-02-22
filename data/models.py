import asyncio
from typing import Optional, Union
from dataclasses import dataclass

from web3 import Web3
from eth_typing import ChecksumAddress
from web3.contract import AsyncContract

from data.eth_convertor import Wei, TokenAmount
from data.config import logger


ECLIPSE_TOKEN = {
    'ETH': {
        'token_address': 'So11111111111111111111111111111111111111112'
    },
    'SOL': {
        'token_address': 'BeRUj3h7BqkbdfFU7FBNYbodgf8GCHodzKvF9aVjNNfL',
        'token_program': 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb'
    },
    'USDC': {
        'token_address': 'AKEWE7Bgh87GPp171b4cJPSSZfmZwQ3KaqYqXoKLNAEE',
        'token_program': 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb'
    },
    'USDT': {
        'token_address': 'CEBP3CqAbW4zdZA57H2wfaSG1QNdzQ72GiQEbQXyW9Tm',
        'token_program': 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb'
    },
    'USDT': {
        'token_address': 'CEBP3CqAbW4zdZA57H2wfaSG1QNdzQ72GiQEbQXyW9Tm',
        'token_program': 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb'
    },
    'tETH': {
        'token_address': 'GU7NS9xCwgNPiAdJ69iusFrRfawjDDPjeMBovhV1d4kn',
        'token_program': 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb'
    }
}


LOCKUP_TABLE_ACCOUNT = {
    'Fsq7DQa13Lx9FvR5QheHigaccRkjiNqfnHQouXyFsg4z': {
        'So11111111111111111111111111111111111111112': 0,
        'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA': 1,
        '11111111111111111111111111111111': 2,
        'SysvarRent111111111111111111111111111111111': 3,
        'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL': 4,
        'whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc': 5,
        'FVG4oDbGv16hqTUbovjyGmtYikn6UBEnazz6RVDMEFwv': 6,
        'ComputeBudget111111111111111111111111111111': 7,
        'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr': 8,
        'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb': 9,
        '9VrJciULifYcwu2CL8nbXdw4deqQgmv7VTzidwgQYBmm': 10,
        'BeRUj3h7BqkbdfFU7FBNYbodgf8GCHodzKvF9aVjNNfL': 11,
        'AKEWE7Bgh87GPp171b4cJPSSZfmZwQ3KaqYqXoKLNAEE': 12
    }   
}


class Network:
    def __init__(self, name: str, rpc: str, chain_id: Optional[int] = None, tx_type: int = 0,
                 coin_symbol: Optional[str] = None, explorer: Optional[str] = None
                 ) -> None:
        self.name: str = name.lower()
        self.rpc: str = rpc
        self.chain_id: Optional[int] = chain_id
        self.tx_type: int = tx_type
        self.coin_symbol: Optional[str] = coin_symbol
        self.explorer: Optional[str] = explorer

        if self.coin_symbol:
            self.coin_symbol = self.coin_symbol.upper()


class Networks:
    # Mainnets
    Ethereum = Network(
        name='Ethereum',
        rpc='https://rpc.ankr.com/eth/',
        chain_id=1,
        tx_type=2,
        coin_symbol='ETH',
        explorer='https://etherscan.io/tx/',
    )

    Arbitrum = Network(
        name='Arbitrum',
        rpc='https://rpc.ankr.com/arbitrum/',
        chain_id=42161,
        tx_type=2,
        coin_symbol='ETH',
        explorer='https://arbiscan.io/tx/',
    )

    Optimism = Network(
        name='Optimism',
        rpc='https://rpc.ankr.com/optimism/',
        chain_id=10,
        tx_type=2,
        coin_symbol='ETH',
        explorer='https://optimistic.etherscan.io/tx/',
    )

    Base = Network(
        name='Base',
        rpc='https://base-rpc.publicnode.com/',
        chain_id=8453,
        tx_type=2,
        coin_symbol='ETH',
        explorer='https://basescan.org/',
    )

    # Testnets
    Goerli = Network(
        name='Goerli',
        rpc='https://rpc.ankr.com/eth_goerli/',
        chain_id=5,
        tx_type=2,
        coin_symbol='ETH',
        explorer='https://goerli.etherscan.io/tx/',
    )

    SaharaAI = Network(
        name='SaharaAI',
        rpc='https://testnet.saharalabs.ai',
        chain_id=313313,
        tx_type=2,
        coin_symbol='SAHARA',
        explorer='https://testnet-explorer.saharalabs.ai/tx/',
    )


@dataclass
class DefaultABIs:
    Token = [
        {
            'constant': True,
            'inputs': [],
            'name': 'name',
            'outputs': [{'name': '', 'type': 'string'}],
            'payable': False,
            'stateMutability': 'view',
            'type': 'function'
        },
        {
            'constant': True,
            'inputs': [],
            'name': 'symbol',
            'outputs': [{'name': '', 'type': 'string'}],
            'payable': False,
            'stateMutability': 'view',
            'type': 'function'
        },
        {
            'constant': True,
            'inputs': [],
            'name': 'totalSupply',
            'outputs': [{'name': '', 'type': 'uint256'}],
            'payable': False,
            'stateMutability': 'view',
            'type': 'function'
        },
        {
            'constant': True,
            'inputs': [],
            'name': 'decimals',
            'outputs': [{'name': '', 'type': 'uint256'}],
            'payable': False,
            'stateMutability': 'view',
            'type': 'function'
        },
        {
            'constant': True,
            'inputs': [{'name': 'who', 'type': 'address'}],
            'name': 'balanceOf',
            'outputs': [{'name': '', 'type': 'uint256'}],
            'payable': False,
            'stateMutability': 'view',
            'type': 'function'
        },
        {
            'constant': True,
            'inputs': [{'name': '_owner', 'type': 'address'}, {'name': '_spender', 'type': 'address'}],
            'name': 'allowance',
            'outputs': [{'name': 'remaining', 'type': 'uint256'}],
            'payable': False,
            'stateMutability': 'view',
            'type': 'function'
        },
        {
            'constant': False,
            'inputs': [{'name': '_spender', 'type': 'address'}, {'name': '_value', 'type': 'uint256'}],
            'name': 'approve',
            'outputs': [],
            'payable': False,
            'stateMutability': 'nonpayable',
            'type': 'function'
        },
        {
            'constant': False,
            'inputs': [{'name': '_to', 'type': 'address'}, {'name': '_value', 'type': 'uint256'}],
            'name': 'transfer',
            'outputs': [], 'payable': False,
            'stateMutability': 'nonpayable',
            'type': 'function'
        }]


class Wallet:
    def __init__(self, client) -> None:
        self.client = client

    async def balance(self, token_address: Optional[str] = None,
                      address: Optional[ChecksumAddress] = None) -> Union[Wei, TokenAmount]:
        if not address:
            address = self.client.account.address

        address = Web3.to_checksum_address(address)
        if not token_address:
            return Wei(await self.client.w3.eth.get_balance(account=address))

        token_address = Web3.to_checksum_address(token_address)
        contract = await self.client.contracts.get_contract(contract_address=token_address)
        return TokenAmount(
            amount=await contract.functions.balanceOf(address).call(),
            decimals=await contract.functions.decimals().call(),
            wei=True
        )

    async def nonce(self, address: Optional[ChecksumAddress] = None) -> int:
        if not address:
            address = self.client.account.address
        return await self.client.w3.eth.get_transaction_count(address)

class Contracts:
    def __init__(self, client) -> None:
        self.client = client

    async def get_contract(self,
                           contract_address: ChecksumAddress,
                           abi: Union[list, dict] = DefaultABIs
                           ) -> AsyncContract:
        return self.client.w3.eth.contract(address=contract_address, abi=abi)


class Transactions:
    def __init__(self, client):
        self.client = client

    @staticmethod
    async def gas_price(w3: Web3, max_retries=30) -> Wei:
        retries = 0
        while retries < max_retries:
            try:
                return Wei(await w3.eth.gas_price)
            except asyncio.exceptions.TimeoutError:
                logger.debug(f"Retry {retries + 1}/{max_retries} due to TimeoutError ETH gas price")
                retries += 1

        raise ValueError(f"Unable to get gas price after {max_retries} retries")
