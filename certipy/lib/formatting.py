from typing import Callable, List, Tuple

from certipy.lib.logger import logging


def to_pascal_case(snake_str: str) -> str:
    components = snake_str.split("_")
    return "".join(x.title() for x in components)


def pretty_print(
    d: dict, indent: int = 0, padding: int = 40, print: Callable = print
) -> None:
    if isinstance(d, dict):
        for key, value in d.items():
            if isinstance(value, str) or isinstance(value, int):
                print(("  " * indent + str(key)).ljust(padding, " ") + ": %s" % value)
            elif isinstance(value, dict):
                print("  " * indent + str(key))
                pretty_print(value, indent=indent + 1, print=print)
            elif isinstance(value, list):
                if len(value) > 0 and isinstance(value[0], dict):
                    print("  " * indent + str(key))
                    for v in value:
                        pretty_print(v, indent=indent + 1, print=print)
                else:
                    print(
                        ("  " * indent + str(key)).ljust(padding, " ")
                        + ": %s"
                        % (
                            ("\n" + " " * padding + "  ").join(
                                map(lambda x: str(x), value)
                            )
                        )
                    )
            elif isinstance(value, tuple):
                print("  " * indent + str(key))
                for v in value:
                    pretty_print(v, indent=indent + 1, print=print)
            elif value is None:
                continue
            else:
                # Shouldn't end up here
                raise NotImplementedError("Not implemented: %s" % type(value))
    else:
        # Shouldn't end up here
        raise NotImplementedError("Not implemented: %s" % type(d))


def print_certificate_identifications(identifications: List[Tuple[str, str]]):
    if len(identifications) > 1:
        logging.info("Got certificate with multiple identifications")
        for id_type, id_value in identifications:
            print("    %s: %s" % (id_type, repr(id_value)))
    elif len(identifications) == 1:
        logging.info(
            "Got certificate with %s %s"
            % (identifications[0][0], repr(identifications[0][1]))
        )
    else:
        logging.info("Got certificate without identification")
