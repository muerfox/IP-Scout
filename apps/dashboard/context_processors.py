from django.http import HttpRequest

from .nav import NAV_TREE


def nav_context(request: HttpRequest) -> dict:
    return {"nav_tree": NAV_TREE}
