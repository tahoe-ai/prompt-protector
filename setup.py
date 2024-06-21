from setuptools import find_packages, setup
import pathlib

# The directory containing this file
HERE = pathlib.Path(__file__).parent

# The text of the README file
README = (HERE / "README.md").read_text()

setup(
    name='prompt_protector',
    package_dir={'': 'src'},  # Tell setuptools that package modules are under src
    packages=find_packages(where='src'),  # Look for packages in src directory
    version='0.1',
    description='A library to help protect LLM inputs and outputs',
    author='Tahoe-AI',
    long_description=README,
    long_description_content_type='text/markdown',
    install_requires=['openai',
                      'asyncio',
                      'aiohttp',
                      'google-cloud-datastore'],
    tests_require=['pytest==4.4.1'],
    test_suite='tests',
)