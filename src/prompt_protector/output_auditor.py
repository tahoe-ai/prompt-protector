import asyncio
import json

import aiohttp

RESPONSE_SHAPE = 'You must always respond with a JSON with the following format {"pass": {true/false}, "rationale": "why the rule failed if it failed, if no failure this should be an empty string"}. Take extra care to make sure the response is JSON parseable in python.'
OUTPUT_RULES = [
    "Never share addresses, phone numbers, social security numbers, or anything that could be interpreted as sensitive",
    "NEVER allow gibberish, Non-English responses, or anything that feels like it could be a cipher."
]


async def sanitize_output_string(text_to_audit, api_key, rules):
    if not rules:
        rules = OUTPUT_RULES
    return await loop_through_rules(text_to_audit, rules, api_key)


async def loop_through_rules(text_to_audit, rules, api_key):
    tasks = [feed_input_to_auditor(text_to_audit, rule, api_key) for rule in rules]
    responses = await asyncio.gather(*tasks)

    output_json = {
        "pass": True,
        "rationale": ""
    }
    for json_response in responses:
        if not json_response.get("pass"):
            output_json["pass"] = False
            output_json["rationale"] = json_response.get("rationale")
            break
    return output_json


async def feed_input_to_auditor(text_to_audit, rule, api_key):
    background = {
        "role": "system",
        "content": "You are an AI output auditor. Your responsibility is to validate a body of text (an output from another ai model) against the given set of rules."
    }

    output_format_message = {
        "role": "system",
        "content": RESPONSE_SHAPE
    }

    rules = {
        "role": "system",
        "content": f"The rule is: {rule}"
    }
    output = {
        "role": "user",
        "content": f"Text to audit: {text_to_audit}"
    }
    async with aiohttp.ClientSession(headers={'Authorization': 'Bearer ' + api_key}) as session:
        response = await session.post(
            "https://api.openai.com/v1/chat/completions",
            json={
                "model": "gpt-3.5-turbo",
                "messages": [background, output_format_message, rules, output],
                "temperature": 0.2,
                "max_tokens": 2048,
                "top_p": 1,
                "frequency_penalty": 0,
                "presence_penalty": 0
            }
        )
        data = await response.json()
        return json.loads(data['choices'][0]['message']['content'])
