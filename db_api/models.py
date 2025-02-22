import datetime

from data.auto_repr import AutoRepr
from sqlalchemy import Column, Integer, Text, Boolean, DateTime
from sqlalchemy.orm import declarative_base


Base = declarative_base()


class Accounts(Base, AutoRepr):
    __tablename__ = 'accounts'

    id = Column(Integer, primary_key=True)

    evm_pk = Column(Text, unique=True)
    evm_address = Column(Text, unique=True)
    proxy = Column(Text)
    email = Column(Text)

    # twitter
    twitter_token = Column(Text)
    twitter_account_status = Column(Text)

    # discord
    discord_token = Column(Text)
    user_agent = Column(Text)

    # galxe 
    galxe_register = Column(Boolean)

    # sahara
    sahara_daily = Column(DateTime)
    sahara_onchain_daily = Column(DateTime)
    sahara_faucet = Column(DateTime)
    sahara_shard_amount = Column(Integer)
    sahara_balance = Column(Integer)
    finished_parse_sahara_balance = Column(Boolean)
    gobi_desert_social_media = Column(Boolean)
    gobi_desert_twitter_task = Column(Boolean)

    finished = Column(Boolean)
    

    def __init__(
            self,
            evm_pk: str,
            evm_address: str,
            proxy: str,
            email: str,
            twitter_token: str,
            discord_token: str,
            user_agent: str,
    ) -> None:
        
        self.evm_pk = evm_pk
        self.evm_address = evm_address
        self.proxy = proxy
        self.email = email

        # twitter
        self.twitter_token = twitter_token
        self.twitter_account_status = 'OK'

        # discord
        self.discord_token = discord_token
        self.user_agent = user_agent

        # galxe
        self.galxe_register = False

        # sahara
        self.sahara_daily = datetime.datetime(1970, 1, 1)
        self.sahara_onchain_daily = datetime.datetime(1970, 1, 1)
        self.sahara_faucet = datetime.datetime(1970, 1, 1)
        self.sahara_shard_amount = 0
        self.sahara_balance = 0
        self.finished_parse_sahara_balance = 0
        self.gobi_desert_social_media = False
        self.gobi_desert_twitter_task = False

        self.finished = False