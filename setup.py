from setuptools import setup, find_packages

setup(
    name="cybersentry",
    version="0.1.0",
    description="Developer-first Security Simulator + Defense Engine",
    author="CyberSentry",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "typer[all]>=0.9.0",
        "rich>=13.7.1",
        "fastapi>=0.111.0",
        "uvicorn[standard]>=0.29.0",
        "pydantic>=2.7.1",
        "pydantic-settings>=2.2.1",
        "sqlalchemy>=2.0.30",
        "aiosqlite>=0.20.0",
        "httpx>=0.27.0",
        "requests>=2.31.0",
        "python-dotenv>=1.0.1",
        "packaging>=24.0",
        "tabulate>=0.9.0",
        "jinja2>=3.1.4",
    ],
    entry_points={
        "console_scripts": [
            "cybersentry=cybersentry.main:app",
            "cs=cybersentry.main:app",
        ],
    },
)
