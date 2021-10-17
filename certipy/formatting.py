# Certipy - Active Directory certificate abuse
#
# Description:
#   Formatting utilities
#
# Authors:
#   @ly4k (https://github.com/ly4k)
#


def dn_to_components(dn: str) -> list[tuple["str", "str"]]:
    components = []
    component = ""
    escape_sequence = False
    for c in dn:
        if c == "\\":
            escape_sequence = True
        elif escape_sequence and c != " ":
            escape_sequence = False
        elif c == ",":
            if "=" in component:
                attr_name, _, value = component.partition("=")
                component = (attr_name, value)
                components.append(component)
                component = ""
                continue

        component += c

    attr_name, _, value = component.partition("=")
    component = (attr_name, value)
    components.append(component)
    return components


def dn_to_fqdn(dn: str) -> str:
    components = dn_to_components(dn)

    dc_components: list[str] = []

    for k, v in components:
        k = k.replace(" ", "").lower()
        if k == "dc":
            dc_components.append(v)

    return ".".join(dc_components)


def to_pascal_case(snake_str: str) -> str:
    components = snake_str.split("_")
    return "".join(x.title() for x in components)


def pretty_print(d, indent=0, padding=40):
    if isinstance(d, dict):
        for key, value in d.items():
            if isinstance(value, str) or isinstance(value, int):
                print(("  " * indent + str(key)).ljust(padding, " ") + ": %s" % value)
            elif isinstance(value, dict):
                print("  " * indent + str(key))
                pretty_print(value, indent=indent + 1)
            elif isinstance(value, list):
                if len(value) > 0 and isinstance(value[0], dict):
                    print("  " * indent + str(key))
                    for v in value:
                        pretty_print(v, indent=indent + 1)
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
                    pretty_print(v, indent=indent + 1)
            else:
                # Shouldn't end up here
                raise NotImplementedError("Not implemented: %s" % type(value))
    else:
        # Shouldn't end up here
        raise NotImplementedError("Not implemented: %s" % type(d))
