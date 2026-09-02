from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="reconx",
    version="1.1.0",
    author="jude84162-sys",
    author_email="",
    description="All-in-One OSINT Suite - Username, Email, Domain, IP Intelligence",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/jude84162-sys/ReconX",
    project_urls={
        "Bug Tracker": "https://github.com/jude84162-sys/ReconX/issues",
        "Source": "https://github.com/jude84162-sys/ReconX",
    },
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=4.0",
            "pytest-timeout>=2.0",
            "flake8>=6.0",
            "black>=23.0",
            "isort>=5.12",
            "bandit>=1.7",
            "build>=1.0",
            "twine>=4.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "reconx=reconx.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Environment :: Console",
        "Operating System :: OS Independent",
        "Natural Language :: English",
    ],
)}
