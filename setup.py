from setuptools import setup, find_packages

setup(
    name="x509dostool",
    version="1.0.2",
    author="Bing Shi",
    author_email="roadicing@gmail.com",
    description="A tool for crafting certificates and detecting bugs in implementations related to certificates.",
    license="MIT",
    packages=find_packages(),
    install_requires=[
        "psutil==6.0.0",
        "pyasn1==0.6.0",
        "pyasn1_modules==0.4.0",
        "pycryptodome==3.20.0"
    ],
    entry_points={
        "console_scripts": [
            "x509dostool=x509dostool.tool:main",
        ],
    },
    python_requires=">=3.8",
    include_package_data=True,
    package_data={
        "x509dostool": ["config.json"]
    },
)

