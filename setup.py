#!/usr/bin/env python3
"""
AgentPimentBleu - Smart Security Scanner for Git Repositories
Setup script for the AgentPimentBleu package.
"""

from setuptools import setup, find_packages

with open("requirements.txt") as f:
    requirements = f.read().splitlines()

setup(
    name="agent-piment-bleu",
    version="0.1.0",
    description="Smart Security Scanner for Git Repositories",
    author="Brieuc Crosson",
    author_email="briossant.com@gmail.com",
    url="https://github.com/briossant/AgentPimentBleu",
    packages=find_packages(),
    py_modules=["app"],
    include_package_data=True,
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "agent-piment-bleu=app:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
    python_requires=">=3.8",
)
