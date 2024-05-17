#!/usr/bin/python3

from zenlib.util import get_kwargs
from cattleguard import CattleGuard


def select_handle(cattle_guard):
    print(f"Found nvram handles: {', '.join([str(index) + ': ' + handle for index, handle in enumerate(cattle_guard.handles)])}")
    while True:
        try:
            return cattle_guard.handles[int(input("Enter the index of the handle to use: "))]
        except ValueError:
            cattle_guard.logger.error("Invalid input, please enter an integer")
        except IndexError:
            cattle_guard.logger.warning("Invalid index, please enter a valid index")
        else:
            break


def read_map(cattle_guard):
    while True:
        try:
            cattle_guard.read_map(select_handle(cattle_guard))
        except RuntimeError as e:
            cattle_guard.logger.error(f"Error reading map: {e}")
            if input("Try again? (y/n): ").lower() != 'y':
                return
        else:
            break


def main():
    arguments = [{'flags': ['-c', '--config'], 'action': 'store', 'help': 'the config file path'}]
    kwargs = get_kwargs(package="cattleguard", description="Wraps LUKS keys with the TPM", arguments=arguments)
    cattle_guard = CattleGuard(**kwargs)
    cattle_guard.init_primary()


if __name__ == "__main__":
    main()
