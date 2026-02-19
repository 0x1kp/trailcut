from setuptools import setup, find_packages

setup(
    name="trailcut",
    version="0.1.0",
    description="CloudTrail log investigation tool for AWS incident response",
    author="trailcut",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "click>=8.0",
        "boto3>=1.26",
    ],
    entry_points={
        "console_scripts": [
            "trailcut=trailcut.cli:cli",
        ],
    },
)
