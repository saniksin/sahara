import random
from typing import Optional

from web3 import AsyncWeb3
from web3.eth import AsyncEth
from eth_account.signers.local import LocalAccount
from eth_typing import ChecksumAddress

from data.config import logger
from data.models import Wallet, Contracts, Transactions, Network, Networks, TokenAmount
from db_api.database import Accounts


class EthClient:
    network: Network
    account: Optional[LocalAccount]
    w3: AsyncWeb3

    def __init__(
            self, 
            private_key: Optional[str] = None, 
            network: Network = Networks.Ethereum,
            proxy: Optional[str] = None, 
            user_agent: Optional[str] = None,
        ) -> None:

        self.network = network
        self.headers = {
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.9',
            'content-type': 'application/json',
            'user-agent': user_agent
        }
        
        self.proxy = proxy

        self.w3 = AsyncWeb3(
            provider=AsyncWeb3.AsyncHTTPProvider(
                endpoint_uri=self.network.rpc,
                request_kwargs={'proxy': self.proxy, 'headers': self.headers}
            ),
            modules={'eth': (AsyncEth,)},
            middleware=[]
        )
        
        if private_key:
            self.account = self.w3.eth.account.from_key(private_key=private_key)

        else:
            logger.warning('RANDOM PRIVATE KEY GENERATED!')
            self.account = self.w3.eth.account.create(extra_entropy=str(random.randint(1, 999_999_999)))
        
        self.wallet = Wallet(self)
        self.contracts = Contracts(self)
        self.transactions = Transactions(self)
    

    async def send_native(self, data: Accounts, amount: TokenAmount, address: Optional[ChecksumAddress] = None):

        nonce = await self.wallet.nonce()
        max_priority_fee_per_gas = await self.w3.eth.max_priority_fee
        base_fee = (await self.w3.eth.fee_history(1, "latest"))["baseFeePerGas"][-1]
        max_fee_per_gas = base_fee + max_priority_fee_per_gas

        multiplier = random.uniform(1.0, 1.2)  # от 100% до 120%
        max_fee_per_gas = await self.w3.eth.gas_price
        max_fee_per_gas = int(max_fee_per_gas * multiplier)
        +п

        tx = {
            "type": self.network.tx_type,
            "chainId": self.network.chain_id,
            "nonce": nonce,
            "to": address,
            "value": amount.Wei, 
            "maxPriorityFeePerGas": max_priority_fee_per_gas,
            "maxFeePerGas": max_fee_per_gas,
            "gas": 21000,
        }

        signed_txn = self.w3.eth.account.sign_transaction(tx, self.account._private_key)

        try:
            # Отправка транзакции
            tx_hash = await self.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
            logger.info(f"[{data.id}] | {data.evm_address} | Транзакция отправлена! Ожидаю статус выполнения...")

            # Ожидание выполнения транзакции
            receipt = await self.w3.eth.wait_for_transaction_receipt(tx_hash)
            
            # Проверка статуса транзакции
            if receipt.status == 1:
                return True, tx_hash.hex()
            else:
                logger.warning(f"[{data.id}] | {data.evm_address} | Транзакция не выполнена (статус != 1). Хэш: {self.network.explorer}{tx_hash.hex()}")
                return False, None

        except Exception as e:
            logger.error(f"[{data.id}] | {data.evm_address} | Ошибка при отправке транзакции: {e}")
            return False, None