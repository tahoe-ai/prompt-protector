from setuptools import find_packages, setup

setup(
    name='prompt_protector',
    package_dir={'': 'src'},  # Tell setuptools that package modules are under src
    packages=find_packages(where='src'),  # Look for packages in src directory
    version='0.1',
    description='A library to help protect LLM inputs and outputs',
    author='Reefly.Ai',
    install_requires=['openai',
                      'asyncio',
                      'aiohttp',
                      'google-cloud-datastore'],
    tests_require=['pytest==4.4.1'],
    test_suite='tests',
)