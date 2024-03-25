from pathlib import Path
from rich.console import Console
from json import load
from handlers.profile.helper import BREADS_FOLDER, get_current_profile

BREADS_FOLDER = Path(BREADS_FOLDER)
console = Console()


def get_data(value) -> None:
    if get_current_profile() == "None":
        console.print(
            "[red][!][/] You need to load a profile first, use 'load_profile' command"
        )
        return None, None

    settings_json_file = f"{BREADS_FOLDER}/{get_current_profile()}/settings.json"

    with open(settings_json_file, "r") as settings_file:
        data = load(settings_file)

        data_to_get = data[value]
        return data_to_get


def get_username() -> None:
    username = get_data("username")
    username = username.split("\\")[1]
    return username


def get_password() -> None:
    return get_data("password")


def get_host() -> None:
    return get_data("host")


def get_domain() -> None:
    return get_data("domain")


def get_uuid() -> None:
    return get_data("profile_uuid")
