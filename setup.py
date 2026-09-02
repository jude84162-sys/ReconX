"""Compatibility entry point for legacy ``python setup.py`` commands.

Project metadata and package configuration live in ``pyproject.toml`` so
there is only one source of truth for builds and installed entry points.
"""

from setuptools import setup


if __name__ == "__main__":
    setup()
