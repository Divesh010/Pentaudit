from setuptools import setup, find_packages

setup(
    name="pentaudit",
    version="1.0.0",
    author="Divesh Gupta",
    author_index="divesh.gupta@example.com", # Placeholder contact
    description="Autonomous Pentest Platform & AI Security Tool Auditor",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/diveshgupta/pentaudit",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
    install_requires=[
        "python-nmap>=0.7.1",
        "requests>=2.31.0",
        "rich>=13.7.0",
        "jinja2>=3.1.3",
        "colorama>=0.4.6",
    ],
    entry_points={
        "console_scripts": [
            "pentaudit=pentaudit.main:main",
        ],
    },
)
