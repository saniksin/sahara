import asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import OperationalError

from db_api.database import db, Accounts, get_accounts
from data.config import logger


async def migrate():
    async with AsyncSession(db.engine) as session:

        try:
            await session.execute(
                text("""
                    ALTER TABLE accounts
                    ADD COLUMN sahara_faucet DATETIME DEFAULT '1970-01-01 00:00:00';
                """)
            )
        except OperationalError:
            pass

        try:
            await session.execute(
                text("""
                    ALTER TABLE accounts
                    ADD COLUMN gobi_desert_social_media BOOLEAN DEFAULT 0;
                """)
            )
        except OperationalError:
            pass

        try:
            await session.execute(
                text("""
                    ALTER TABLE accounts
                    ADD COLUMN gobi_desert_twitter_task BOOLEAN DEFAULT 0;
                """)
            )
        except OperationalError:
            pass

        try:
            await session.execute(
                text("""
                ALTER TABLE accounts
                ADD COLUMN twitter_account_status TEXT DEFAULT 'OK';
            """)
            )
        except OperationalError:
            pass

        try:
            await session.execute(
                text("""
                ALTER TABLE accounts
                ADD COLUMN sahara_shard_amount INTEGER DEFAULT 0;
            """)
            )
        except OperationalError:
            pass
    
        try:
            await session.execute(
                text("""
                ALTER TABLE accounts
                ADD COLUMN sahara_balance INTEGER DEFAULT 0;
            """)
            )
        except OperationalError:
            pass

        try:
            await session.execute(
                text("""
                ALTER TABLE accounts
                ADD COLUMN finished_parse_sahara_balance BOOLEAN DEFAULT 0;
            """)
            )
        except OperationalError:
            pass

        try:
            await session.execute(
                text("""
                ALTER TABLE accounts
                ADD COLUMN sahara_onchain_daily DATETIME DEFAULT '1970-01-01 00:00:00';
            """)
            )
        except OperationalError:
            pass
        
        try:
            await session.execute(
                text("""
                ALTER TABLE accounts
                ADD COLUMN finished BOOLEAN DEFAULT 0;
            """)
            )
        except OperationalError:
            pass

        try:
            await session.execute(
                text("""
                ALTER TABLE accounts
                ADD COLUMN account_registration_in_DSP BOOLEAN DEFAULT 0;
            """)
            )
        except OperationalError:
            pass

        try:
            await session.execute(
                text("""
                ALTER TABLE accounts
                ADD COLUMN airdrop_checked BOOLEAN DEFAULT 0;
            """)
            )
        except OperationalError:
            pass

        try:
            await session.execute(
                text("""
                ALTER TABLE accounts
                ADD COLUMN airdrop_eligible BOOLEAN DEFAULT 0;
            """)
            )
        except OperationalError:
            pass

        try:
            await session.execute(
                text("""
                ALTER TABLE accounts
                ADD COLUMN allocation_breakdown INTEGER DEFAULT 0;
            """)
            )
        except OperationalError:
            pass

        try:
            await session.execute(
                text("""
                ALTER TABLE accounts
                ADD COLUMN stage_1 INTEGER DEFAULT 0;
            """)
            )
        except OperationalError:
            pass

        try:
            await session.execute(
                text("""
                ALTER TABLE accounts
                ADD COLUMN stage_2 INTEGER DEFAULT 0;
            """)
            )
        except OperationalError:
            pass

        try:
            await session.execute(
                text("""
                ALTER TABLE accounts
                ADD COLUMN stage_3 INTEGER DEFAULT 0;
            """)
            )
        except OperationalError:
            pass

        try:
            await session.execute(
                text("""
                ALTER TABLE accounts
                ADD COLUMN stage_4 INTEGER DEFAULT 0;
            """)
            )
        except OperationalError:
            pass

        try:
            await session.execute(
                text("""
                ALTER TABLE accounts
                ADD COLUMN stage_5 INTEGER DEFAULT 0;
            """)
            )
        except OperationalError:
            pass

        try:
            await session.execute(
                text("""
                ALTER TABLE accounts
                ADD COLUMN stage_6 INTEGER DEFAULT 0;
            """)
            )
        except OperationalError:
            pass

        try:
            await session.execute(
                text("""
                ALTER TABLE accounts
                ADD COLUMN stage_7 INTEGER DEFAULT 0;
            """)
            )
        except OperationalError:
            pass

        await session.commit()
        await session.close()

    logger.success('Migration completed.')
