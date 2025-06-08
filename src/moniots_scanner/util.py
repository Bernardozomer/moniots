from alive_progress import alive_bar, alive_it

RES_DIR = "./res"


def pbar(iterable, desc=None, total=None):
    """A standard alive-progress wrapper with common parameters."""
    return alive_it(
        iterable,
        total=total,
        title=desc,
        bar="smooth",
        spinner="dots_waves",
    )


def spinner(desc=None):
    return alive_bar(
        title=desc,
        unknown="waves",
        bar=None,
        stats=None,
        monitor=None,
    )
