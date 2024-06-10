import aiohttp
import json
import openai
import time
from .settings import OPEN_AI_KEY, RESPONSE_SHAPE


def feed_input_to_chat_gpt(input_string, last_message):
    messages_list = []
    if last_message is not None:
        last_user_message = {
            "role": "user",
            "content": last_message.get("user_input")
        }
        messages_list.append(last_user_message)
        last_gpt_message = {
            "role": "assistant",
            "content": last_message.get("system_response")
        }
        messages_list.append(last_gpt_message)
    input_message = {
        "role": "user",
        "content": input_string
    }
    messages_list.append(input_message)
    #print(f'messages list: {messages_list}')
    start = time.time()
    openai.api_key = OPEN_AI_KEY
    response = openai.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=messages_list,
        temperature=0.2,
        max_tokens=2048,
        top_p=1,
        frequency_penalty=0,
        presence_penalty=0
    )
    end = time.time()
    # Debug statements
    #print(f"Time spent in initial response: {end - start}")
    #print(f"initial response: {response.choices[0].message.content}")
    return response.choices[0].message.content

async def feed_input_to_auditor(text_to_audit, rule):
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
    async with aiohttp.ClientSession(headers={'Authorization': 'Bearer ' + OPEN_AI_KEY}) as session:
        response = await session.post(
            "https://api.openai.com/v1/chat/completions",
            json={
                "model": "gpt-4-turbo-preview",
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


async def loop_through_rules(text_to_audit):
    tasks = [feed_input_to_auditor(text_to_audit, rule) for rule in RULES]
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

def prepare_messages(input_string, last_message):
    """
    Prepare the messages payload for the OpenAI API based on the user input and the last message.

    Args:
        input_string (str): The user's input string.
        last_message (dict): The last message exchanged in the conversation, if any.

    Returns:
        list: A list of message objects for the OpenAI API.
    """
    messages_list = []
    # Example: Add your system, previous conversation messages here
    # This function needs to be implemented based on how you want to construct
    # the conversation context for the API call.
    
    return messages_list
