from setuptools import setup, find_packages

setup(
    name="vibe-check-suite",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "click>=8.0.0",
        "rich>=12.0.0",
        "requests>=2.28.0",
        "pyjwt>=2.6.0",
        "colorama>=0.4.6"
    ],
    entry_points={
        'console_scripts': [
            'vibecheck=scanner.cli:main',
        ],
    },
)