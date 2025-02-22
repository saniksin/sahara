from typing import List, Union
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.future import select
from sqlalchemy import text


class DBException(Exception):
    pass


class DB:
    def __init__(self, db_url: str, **kwargs):
        """
        Initializes a class.
        :param str db_url: a URL containing all the necessary parameters to connect to a DB
        """
        self.db_url = db_url
        self.engine = create_async_engine(self.db_url, **kwargs)
        self.Base = None

    async def create_tables(self, base):
        """
        Creates tables.
        :param base: a base class for declarative class definitions
        """
        async with self.engine.begin() as conn:
            await conn.run_sync(base.metadata.create_all)

    async def all(self, query):
        async with AsyncSession(self.engine) as session:
            result = await session.execute(query)
            return result.scalars().all()

    async def one(self, entity, *criterion, from_the_end: bool = False):
        """
        Fetches one row.
        :param entity: an ORM entity
        :param criterion: criterion for rows filtering
        :param from_the_end: get the row from the end
        :return list: found row or None
        """
        query = select(entity).filter(*criterion)
        all_rows = await self.all(query)
        if all_rows:
            return all_rows[-1] if from_the_end else all_rows[0]
        return None

    async def execute(self, query, *args):
        """
        Executes SQL query.
        :param query: the query
        :param args: any additional arguments
        """
        async with self.engine.connect() as conn:
            result = await conn.execute(text(query), *args)
            await conn.commit()
            return result

    async def insert(self, row: Union[object, List[object]]):
        """
        Inserts rows.
        :param Union[object, List[object]] row: an ORM entity or list of entities
        """
        async with AsyncSession(self.engine) as session:
            if isinstance(row, list):
                session.add_all(row)
            elif isinstance(row, object):
                session.add(row)
            else:
                raise DBException('Wrong type!')
            await session.commit()
