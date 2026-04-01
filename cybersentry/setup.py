from setuptools import setup, find_packages

setup(
    name="cybersentry",
    version="0.1.0",
    description="Developer-first Security Simulator + Defense Engine",
    author="CyberSentry",
    packages=find_packages(),
    python_requires=">=3.11",
    install_requires=[
        "typer[all]>=0.12.3",
        "rich>=13.7.1",
        "fastapi>=0.111.0",
        "uvicorn[standard]>=0.29.0",
        "pydantic>=2.7.1",
        "pydantic-settings>=2.2.1",
        "sqlalchemy>=2.0.30",
        "aiosqlite>=0.20.0",
        "httpx>=0.27.0",
        "requests>=2.31.0",
        "bandit>=1.7.8",
        "pip-audit>=2.7.3",
        "detect-secrets>=1.4.0",
        "reportlab>=4.1.0",
        "jinja2>=3.1.4",
        "python-dotenv>=1.0.1",
        "toml>=0.10.2",
        "gitpython>=3.1.43",
        "packaging>=24.0",
        "tabulate>=0.9.0",
    ],
    entry_points={
        "console_scripts": [
            "cybersentry=cybersentry.main:app",
            "cs=cybersentry.main:app",  # short alias
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Programming Language :: Python :: 3.11",
    ],
)
