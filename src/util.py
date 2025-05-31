from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable

from tqdm import tqdm

import models

RES_DIR = "./res"


def batch_test(
    devices: list[models.Device], desc: str, test_func: Callable, *args
) -> dict[models.Device, Any]:
    """Run a test function in parallel over all devices."""
    results = {}
    with ThreadPoolExecutor() as pool:
        futures = {pool.submit(test_func, d, *args): d for d in devices}

        for fut in pbar(as_completed(futures), desc=desc, total=len(futures)):
            device = futures[fut]
            results[device] = fut.result()

    return results


def pbar(iterable=None, desc=None, total=None, ncols=120, colour="green"):
    """A standard tqdm wrapper with common parameters."""
    return tqdm(iterable, desc=desc, total=total, ncols=ncols, colour=colour)
