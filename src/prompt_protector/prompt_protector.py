import asyncio
import time

import openai

from prompt_protector.input_auditor import sanitize_input_string
from prompt_protector.output_auditor import sanitize_output_string


class PromptProtector:
    def __init__(self, api_key=None, output_rules=None):
        self._initialized = None
        if not self._initialized:
            self._api_key = api_key
            self.output_rules = output_rules
            self._initialized = True

    def sanitize_input(self, text_to_audit):
        return sanitize_input_string(text_to_audit, self._api_key)

    def sanitize_output(self, text_to_audit):
        return asyncio.run(sanitize_output_string(text_to_audit, self._api_key, self.output_rules))

    def generate_failure_message(self):
        start = time.time()
        output_format_message = {
            "role": "system",
            "content": "You are a helpful auditor that will explain the reasoning for blocking a particular request"
        }
        openai.api_key = self._api_key
        response = openai.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[output_format_message],
            temperature=0.2,
            max_tokens=2048,
            top_p=1,
            frequency_penalty=0,
            presence_penalty=0
        )
        end = time.time()
        # Debug statements
        # print(f"Time spent in initial response: {end - start}")
        # print(f"initial response: {response.choices[0].message.content}")
        return response.choices[0].message.content