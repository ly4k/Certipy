import pkg_resources
from impacket import __path__

try:
    version = pkg_resources.get_distribution("certipy-ad").version
except pkg_resources.DistributionNotFound:
    version = "?"
    print(
        "Cannot determine Certipy version. "
        'If running from source you should at least run "python setup.py egg_info"'
    )
BANNER = "Certipy v{} - by Oliver Lyak (ly4k)\n".format(version)
