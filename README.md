
# Prompt Protector Library

The Prompt Protector Library is a Python package designed for validating AI-generated outputs against predefined rules. It offers a robust solution for sanitizing inputs and ensures that outputs from AI models adhere to specific standards, making it suitable for applications requiring secure and reliable AI interactions.

## Features

- **Input Sanitization**: Checks inputs against a set of predefined rules to prevent malicious or undesired inputs.
- **Output Validation**: Validates AI outputs to ensure they comply with defined rules, enhancing security and reliability.
- **Asynchronous API**: Utilizes asynchronous programming for efficient network operations and API calls.
- **Extensible**: Easily extendable to include more complex validation rules and other AI models.

## Installation

Before installing the Prompt Protector Library, ensure you have Python 3.7 or newer installed on your system.

### Install from PyPI

To install the library directly from PyPI, run:

```bash
pip install prompt-protector
```

### Install from Source

To install the library from the source code, follow these steps:

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/prompt-protector.git
   ```
2. Navigate to the project directory:
   ```bash
   cd prompt-protector
   ```
3. Install the package:
   ```bash
   pip install .
   ```

## Configuration

Set the following environment variables in your system or virtual environment:

- `OPEN_AI_KEY`: Your OpenAI API key.

## Usage

Here's how you can use the Prompt Protector Library in your Python scripts:

### Validating AI Output

```python
from prompt_protector import validate_ai_output
import asyncio

# Example input and channel ID
input_data = "Example input data"
channel_id = "example_channel_id"

# Validate AI output
result = asyncio.run(validate_ai_output(input_data, channel_id))
print(result)
```

### Input Sanitization

The library provides a method to sanitize inputs before processing them with an AI model:

```python
from prompt_protector import sanitize_input
import asyncio

# Sanitize user input
sanitized = asyncio.run(sanitize_input("Check this suspicious string"))
print(sanitized)
```

## Dependencies

- aiohttp
- asyncio
- google-cloud-datastore (if using Google Cloud Datastore for storage)

## Contributing

Contributions are welcome! Please read our contributing guide to learn about our development process, how to propose bugfixes and improvements, and how to build and test your changes to the Prompt Protector Library.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
