import asyncio
from typing import List, Callable, Any
from .logger import Logger

logger = Logger(__name__)

async def run_with_timeout(
    coro: Callable,
    timeout: float,
    default: Any = None
) -> Any:
    """Run coroutine with timeout"""
    try:
        return await asyncio.wait_for(coro, timeout=timeout)
    except asyncio.TimeoutError:
        logger.warning(f"Operation timed out after {timeout} seconds")
        return default
    except Exception as e:
        logger.error(f"Error in async operation: {str(e)}")
        return default 