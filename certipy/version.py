# Initialize version as unknown
version = "?"

# Try modern importlib.metadata approach (Python 3.8+)
try:
    from importlib.metadata import version as get_version

    version = get_version("certipy-ad")
except ImportError:
    # For Python < 3.8, try importlib_metadata backport
    try:
        from importlib_metadata import version as get_version

        version = get_version("certipy-ad")
    except ImportError:
        # Fall back to pkg_resources (setuptools)
        try:
            import pkg_resources

            version = pkg_resources.get_distribution("certipy-ad").version
        except (ImportError, pkg_resources.DistributionNotFound):
            print(
                "Cannot determine Certipy version. "
                'If running from source you should at least run "python setup.py egg_info"'
            )

BANNER = "Certipy v{} - by Oliver Lyak (ly4k)\n".format(version)
